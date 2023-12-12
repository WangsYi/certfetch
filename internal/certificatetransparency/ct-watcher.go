package certificatetransparency

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/d-Rickyy-b/certstream-server-go/internal/certstream"
	"github.com/d-Rickyy-b/certstream-server-go/internal/db"
	"github.com/d-Rickyy-b/certstream-server-go/internal/web"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/scanner"
)

var (
	processedCerts    int64
	processedPrecerts int64
	metrics           = LogMetrics{metrics: make(CTMetrics)}
)

type (
	// OperatorLogs is a map of operator names to a list of CT log urls, operated by said operator.
	OperatorLogs map[string][]string
	// OperatorMetric is a map of CT log urls to the number of certs processed by said log.
	OperatorMetric map[string]int64
	// CTMetrics is a map of operator names to a map of CT log urls to the number of certs processed by said log.
	CTMetrics map[string]OperatorMetric
)

var (
	errCreatingClient    = errors.New("failed to create JSON client")
	errFetchingSTHFailed = errors.New("failed to fetch STH")
)

// LogMetrics is a struct that holds a map of metrics for each CT log grouped by operator.
// Metrics can be accessed and written concurrently through the Get, Set and Inc methods.
type LogMetrics struct {
	mutex   sync.RWMutex
	metrics CTMetrics
}

// GetCTMetrics returns a copy of the internal metrics map.
func (m *LogMetrics) GetCTMetrics() CTMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	copiedMap := make(CTMetrics)

	for operator, urls := range m.metrics {
		copiedMap[operator] = make(OperatorMetric)
		for url, count := range urls {
			copiedMap[operator][url] = count
		}
	}

	return copiedMap
}

// OperatorLogMapping returns a map of operator names to a list of CT logs.
func (m *LogMetrics) OperatorLogMapping() OperatorLogs {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	logOperators := make(map[string][]string, len(m.metrics))

	for operator, urls := range m.metrics {
		urlList := make([]string, len(urls))
		counter := 0

		for url := range urls {
			urlList[counter] = url
			counter++
		}
		logOperators[operator] = urlList
	}

	return logOperators
}

// Get the metric for a given operator and ct url.
func (m *LogMetrics) Get(operator, url string) int64 {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if _, ok := m.metrics[operator]; !ok {
		m.metrics[operator] = make(OperatorMetric)
	}

	return m.metrics[operator][url]
}

// Set the metric for a given operator and ct url.
func (m *LogMetrics) Set(operator, url string, value int64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.metrics[operator]; !ok {
		m.metrics[operator] = make(OperatorMetric)
	}

	m.metrics[operator][url] = value
}

// Inc the metric for a given operator and ct url.
func (m *LogMetrics) Inc(operator, url string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, ok := m.metrics[operator]; !ok {
		m.metrics[operator] = make(OperatorMetric)
	}

	m.metrics[operator][url]++
}

func GetProcessedCerts() int64 {
	return processedCerts
}

func GetProcessedPrecerts() int64 {
	return processedPrecerts
}

func GetCertMetrics() CTMetrics {
	return metrics.GetCTMetrics()
}

func GetLogOperators() map[string][]string {
	return metrics.OperatorLogMapping()
}

// Watcher describes a component that watches for new certificates in a CT log.
type Watcher struct {
	Name       string
	Type       string // "realtime" or "history"
	workers    []*worker
	cancelFunc context.CancelFunc
}

// Start starts the watcher. This method is blocking.
func (w *Watcher) Start() {
	// Get a list of urls of all CT logs
	logList, err := getAllLogs()
	if err != nil {
		log.Println(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	w.cancelFunc = cancel
	certChan := make(chan certstream.Entry, 5000)

	var wg sync.WaitGroup

	// For each CT log, create a worker and start downloading certs
	for _, operator := range logList.Operators {
		for _, transparencyLog := range operator.Logs {
			wg.Add(1)
			ctWorker := worker{
				name:         transparencyLog.Description,
				operatorName: operator.Name,
				ctURL:        transparencyLog.URL,
				entryChan:    certChan,
				watcher:      w,
			}
			w.workers = append(w.workers, &ctWorker)

			// Start a goroutine for each worker
			go func() {
				defer wg.Done()
				ctWorker.startDownloadingCerts(ctx)
			}()
		}
	}

	log.Println("Started CT watcher")
	go certHandler(certChan)

	wg.Wait()
	close(certChan)
}

// Stop stops the watcher.
func (w *Watcher) Stop() {
	log.Printf("Stopping watcher '%s'\n", w.Name)
	w.cancelFunc()
}

// A worker processes a single CT log.
type worker struct {
	name         string
	operatorName string
	ctURL        string
	entryChan    chan certstream.Entry
	mu           sync.Mutex
	running      bool
	watcher      *Watcher
}

// startDownloadingCerts starts downloading certificates from the CT log. This method is blocking.
func (w *worker) startDownloadingCerts(ctx context.Context) {
	// Normalize CT URL. We remove trailing slashes and prepend "https://" if it's not already there.
	w.ctURL = strings.TrimRight(w.ctURL, "/")
	if !strings.HasPrefix(w.ctURL, "https://") && !strings.HasPrefix(w.ctURL, "http://") {
		w.ctURL = "https://" + w.ctURL
	}

	log.Printf("Starting worker for CT log: %s\n", w.ctURL)
	defer log.Printf("Stopping worker for CT log: %s\n", w.ctURL)

	w.mu.Lock()
	if w.running {
		log.Printf("Worker for '%s' already running\n", w.ctURL)
		w.mu.Unlock()

		return
	}

	w.running = true
	w.mu.Unlock()

	for {
		workerErr := w.runWorker(ctx)
		if workerErr != nil {
			if errors.Is(workerErr, errFetchingSTHFailed) {
				log.Printf("Worker for '%s' failed - could not fetch STH\n", w.ctURL)
				return
			} else if errors.Is(workerErr, errCreatingClient) {
				log.Printf("Worker for '%s' failed - could not create client\n", w.ctURL)
				return
			} else if strings.Contains(workerErr.Error(), "no such host") {
				log.Printf("Worker for '%s' failed to resolve host: %s\n", w.ctURL, workerErr)
				return
			}

			log.Printf("Worker for '%s' failed with unexpected error: %s\n", w.ctURL, workerErr)
		}

		// Check if the context was cancelled
		select {
		case <-ctx.Done():
			log.Printf("Context was cancelled; Stopping worker for '%s'\n", w.ctURL)
			return
		default:
			log.Println("Sleeping for 5 seconds")
			time.Sleep(5 * time.Second)
			log.Printf("Restarting worker for '%s'\n", w.ctURL)
			continue
		}
	}
}

// runWorker runs a single worker for a single CT log. This method is blocking.
func (w *worker) runWorker(ctx context.Context) error {
	// userAgent := fmt.Sprintf("Certstream Server v%s (github.com/d-Rickyy-b/certstream-server-go)", config.Version)
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36"
	hc := http.Client{Timeout: 60 * time.Second}
	jsonClient, e := client.New(w.ctURL, &hc, jsonclient.Options{UserAgent: userAgent})
	if e != nil {
		log.Printf("Error creating JSON client: %s\n", e)
		return errCreatingClient
	}

	sth, getSTHerr := jsonClient.GetSTH(ctx)
	if getSTHerr != nil {
		log.Printf("Could not get STH for '%s': %s\n", w.ctURL, getSTHerr)
		return errFetchingSTHFailed
	}
	startIdx := int64(sth.TreeSize)
	if w.watcher.Type == "history" {
		process, err := db.GetProcess(w.name)
		if err != nil {
			log.Printf("cannot get process of %s, err: %v, start from 0\n", w.name, err)
			startIdx = 0
		}
		startIdx = process
	}
	certScanner := scanner.NewScanner(jsonClient, scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     50,
			ParallelFetch: 1,
			StartIndex:    startIdx, // Start at the latest STH to skip all the past certificates
			Continuous:    true,
		},
		Matcher:     scanner.MatchAll{},
		PrecertOnly: false,
		NumWorkers:  1,
		BufferSize:  1000,
	})

	scanErr := certScanner.Scan(ctx, w.foundCertCallback, w.foundPrecertCallback)
	if scanErr != nil {
		log.Println("Scan error: ", scanErr)
		return scanErr
	}

	log.Println("No error from certScanner!")

	return nil
}

// foundCertCallback is the callback that handles cases where new regular certs are found.
func (w *worker) foundCertCallback(rawEntry *ct.RawLogEntry) {
	entry, parseErr := parseCertstreamEntry(rawEntry, w.operatorName, w.name, w.ctURL)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}

	entry.Data.UpdateType = "X509LogEntry"
	w.entryChan <- entry

	atomic.AddInt64(&processedCerts, 1)
}

// foundPrecertCallback is the callback that handles cases where new precerts are found.
func (w *worker) foundPrecertCallback(rawEntry *ct.RawLogEntry) {
	entry, parseErr := parseCertstreamEntry(rawEntry, w.operatorName, w.name, w.ctURL)
	if parseErr != nil {
		log.Println("Error parsing certstream entry: ", parseErr)
		return
	}

	entry.Data.UpdateType = "PrecertLogEntry"
	w.entryChan <- entry
	idx, err := db.GetProcess(w.name)
	if err != nil {
		log.Printf("cannot get process of %s, err:%v", w.name, err)
	}

	if idx < entry.Data.CertIndex {
		err = db.SetProcess(w.name, entry.Data.CertIndex)
		if err != nil {
			log.Printf("cannot set process of %s, err:%v", w.name, err)
		}
	}

	atomic.AddInt64(&processedPrecerts, 1)
}

var curEntries []string

// certHandler takes the entries out of the entryChan channel and broadcasts them to all clients.
// Only a single instance of the certHandler runs per certstream server.
func certHandler(entryChan chan certstream.Entry) {
	var processed int64

	for {
		entry := <-entryChan
		processed++

		if processed%1000 == 0 {
			saveCurEntries()
			log.Printf("Processed %d entries | Queue length: %d\n", processed, len(entryChan))
			// Every thousandth entry, we store one certificate as example
			web.SetExampleCert(entry)
		}
		curEntries = append(curEntries, string(entry.JSON()))
		// Run json encoding in the background and send the result to the clients.
		//web.ClientHandler.Broadcast <- entry

		url := entry.Data.Source.NormalizedURL
		operator := entry.Data.Source.Operator

		metrics.Inc(operator, url)
	}
}

func saveCurEntries() {
	tm := time.Now().Unix()
	dir := "./data/" + strconv.FormatInt(tm/1000, 10)
	_, err := os.Stat(dir)
	if err != nil {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			log.Fatal(err)
		}
	}
	dataStr := "[" + strings.Join(curEntries, ",") + "]"
	f, err := os.Create(dir + "/" + strconv.FormatInt(time.Now().Unix(), 10) + ".json")
	if err != nil {
		log.Fatal(err)
	}
	_, err = f.WriteString(dataStr)
	if err != nil {
		err = f.Close()
		if err != nil {
			log.Fatal(err)
		}
		log.Fatal(err)
	}
	f.Sync()
	err = f.Close()
	if err != nil {
		log.Fatal(err)
	}
	curEntries = []string{}
}

// getAllLogs returns a list of all CT logs.
func getAllLogs() (loglist3.LogList, error) {
	// Download the list of all logs from ctLogInfo and decode json
	resp, err := http.Get(loglist3.LogListURL)
	if err != nil {
		return loglist3.LogList{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return loglist3.LogList{}, errors.New("failed to download loglist")
	}

	bodyBytes, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		log.Panic(readErr)
	}

	allLogs, parseErr := loglist3.NewFromJSON(bodyBytes)
	if parseErr != nil {
		return loglist3.LogList{}, parseErr
	}

	// Initial setup of the urlMetricsMap
	for _, operator := range allLogs.Operators {
		for _, ctlog := range operator.Logs {
			url := normalizeCtlogURL(ctlog.URL)
			metrics.Set(operator.Name, url, 0)
		}
	}

	return *allLogs, nil
}

func normalizeCtlogURL(input string) string {
	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimSuffix(input, "/")

	return input
}
