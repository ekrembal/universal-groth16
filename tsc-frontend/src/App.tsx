import { useState, useEffect, useCallback, useRef } from 'react';
import {
  parseCeremonyFile,
  contribute,
  checkWebGPU,
  formatBytes,
  formatDuration,
} from './ceremony';
import type {
  CeremonyInfo,
  ContributionTiming,
} from './ceremony';
import './App.css';

type AppState =
  | { stage: 'idle' }
  | { stage: 'loaded'; info: CeremonyInfo }
  | { stage: 'contributing'; info: CeremonyInfo; progressStage: string; progressDetail: string; progress: number }
  | { stage: 'done'; info: CeremonyInfo; result: Uint8Array; timing: ContributionTiming }
  | { stage: 'error'; message: string };

function App() {
  const [state, setState] = useState<AppState>({ stage: 'idle' });
  const [useGPU, setUseGPU] = useState(false);
  const [gpuInfo, setGpuInfo] = useState<{ available: boolean; adapterInfo?: string }>({
    available: false,
  });
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Check WebGPU availability on mount (no device is held long-term)
  useEffect(() => {
    checkWebGPU().then((info) => {
      setGpuInfo(info);
      if (info.available) {
        setUseGPU(true);
      }
    });
  }, []);

  const handleFile = useCallback(async (file: File) => {
    try {
      setState({ stage: 'idle' }); // Reset
      const buffer = await file.arrayBuffer();
      const data = new Uint8Array(buffer);
      const info = parseCeremonyFile(data);
      setState({ stage: 'loaded', info });
    } catch (err) {
      setState({
        stage: 'error',
        message: `Failed to parse file: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const handleContribute = useCallback(async () => {
    if (state.stage !== 'loaded') return;
    const { info } = state;

    setState({
      stage: 'contributing',
      info,
      progressStage: 'Starting',
      progressDetail: 'Initializing...',
      progress: 0,
    });

    // Yield to let React render
    await new Promise((r) => setTimeout(r, 50));

    try {
      const result = await contribute(
        info,
        useGPU,
        (progressStage, progressDetail, progress) => {
          setState((prev) => {
            if (prev.stage !== 'contributing') return prev;
            return { ...prev, progressStage, progressDetail, progress };
          });
        },
      );

      setState({
        stage: 'done',
        info,
        result: result.data,
        timing: result.timing,
      });
    } catch (err) {
      setState({
        stage: 'error',
        message: `Contribution failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [state, useGPU]);

  const handleDownload = useCallback(() => {
    if (state.stage !== 'done') return;
    const blob = new Blob([state.result.buffer as ArrayBuffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phase2_contribution_${Date.now()}.bin`;
    a.click();
    URL.revokeObjectURL(url);
  }, [state]);

  const handleReset = useCallback(() => {
    setState({ stage: 'idle' });
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  }, []);

  return (
    <div className="app">
      <header className="header">
        <h1>Groth16 Phase 2 Ceremony</h1>
        <p className="subtitle">PlonkVerifierGroth16Circuit — Trusted Setup Contribution</p>
      </header>

      <main className="main">
        {/* WebGPU Status */}
        <div className="gpu-status">
          <span className={`status-dot ${gpuInfo.available ? 'available' : 'unavailable'}`} />
          <span>
            WebGPU: {gpuInfo.available ? `Available — ${gpuInfo.adapterInfo}` : 'Not available (CPU fallback)'}
          </span>
        </div>

        {/* File Upload */}
        {(state.stage === 'idle' || state.stage === 'error') && (
          <div
            className={`dropzone ${dragOver ? 'drag-over' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <div className="dropzone-content">
              <svg className="upload-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="17 8 12 3 7 8" />
                <line x1="12" y1="3" x2="12" y2="15" />
              </svg>
              <p className="dropzone-text">Drop Phase 2 file here or click to browse</p>
              <p className="dropzone-hint">Accepts .bin files from prepare-ceremony</p>
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".bin,application/octet-stream"
              onChange={handleFileInput}
              hidden
            />
          </div>
        )}

        {/* Error State */}
        {state.stage === 'error' && (
          <div className="error-card">
            <p>{state.message}</p>
            <button className="btn btn-secondary" onClick={handleReset}>Try Again</button>
          </div>
        )}

        {/* Loaded / Contributing / Done States */}
        {(state.stage === 'loaded' || state.stage === 'contributing' || state.stage === 'done') && (
          <>
            {/* Ceremony Info */}
            <div className="info-card">
              <h2>Ceremony State</h2>
              <div className="info-grid">
                <InfoRow label="File size" value={formatBytes(state.info.fileSizeBytes)} />
                <InfoRow label="G1.Z points" value={state.info.g1ZCount.toLocaleString()} />
                <InfoRow label="G1.PKK points" value={state.info.g1PKKCount.toLocaleString()} />
                <InfoRow label="Commitments" value={String(state.info.commitments)} />
                {state.info.sigmaCKKCounts.map((count, i) => (
                  <InfoRow key={i} label={`SigmaCKK[${i}]`} value={count.toLocaleString()} />
                ))}
                <InfoRow label="Total G1 points" value={state.info.totalG1Points.toLocaleString()} />
              </div>
            </div>

            {/* Acceleration Toggle */}
            {state.stage === 'loaded' && (
              <div className="controls">
                <div className="toggle-group">
                  <label className="toggle-label">Acceleration:</label>
                  <button
                    className={`toggle-btn ${!useGPU ? 'active' : ''}`}
                    onClick={() => setUseGPU(false)}
                  >
                    CPU
                  </button>
                  <button
                    className={`toggle-btn ${useGPU ? 'active' : ''}`}
                    onClick={() => gpuInfo.available && setUseGPU(true)}
                    disabled={!gpuInfo.available}
                    title={!gpuInfo.available ? 'WebGPU not available' : ''}
                  >
                    WebGPU
                  </button>
                </div>

                <button className="btn btn-primary" onClick={handleContribute}>
                  Contribute
                </button>

                <button className="btn btn-ghost" onClick={handleReset}>
                  Reset
                </button>
              </div>
            )}

            {/* Progress */}
            {state.stage === 'contributing' && (
              <div className="progress-card">
                <h2>Contributing...</h2>
                <div className="progress-bar-container">
                  <div
                    className="progress-bar"
                    style={{ width: `${Math.max(state.progress * 100, 2)}%` }}
                  />
                </div>
                <div className="progress-info">
                  <span className="progress-stage">{state.progressStage}</span>
                  <span className="progress-detail">{state.progressDetail}</span>
                </div>
              </div>
            )}

            {/* Results */}
            {state.stage === 'done' && (
              <div className="results-card">
                <h2>Contribution Complete</h2>

                <div className="timing-grid">
                  <TimingRow label="Total time" value={state.timing.totalMs} highlight />
                  <TimingRow label="Challenge hash" value={state.timing.challengeMs} />
                  <TimingRow label="Random generation" value={state.timing.randomGenMs} />
                  <TimingRow label="Proof generation" value={state.timing.proofGenMs} />
                  <TimingRow label="Parameter update" value={state.timing.paramUpdateMs} highlight />
                  <TimingRow label="Serialization" value={state.timing.serializeMs + state.timing.parseMs} />
                </div>

                <div className="result-meta">
                  <span>Output: {formatBytes(state.result.length)}</span>
                  <span>Mode: {useGPU ? 'WebGPU' : 'CPU'}</span>
                </div>

                <div className="result-actions">
                  <button className="btn btn-primary" onClick={handleDownload}>
                    Download Contribution
                  </button>
                  <button className="btn btn-secondary" onClick={handleReset}>
                    New Contribution
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </main>

      <footer className="footer">
        <p>Groth16 Phase 2 TSC — BN254 • WebGPU Accelerated</p>
      </footer>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="info-row">
      <span className="info-label">{label}</span>
      <span className="info-value">{value}</span>
    </div>
  );
}

function TimingRow({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className={`timing-row ${highlight ? 'highlight' : ''}`}>
      <span className="timing-label">{label}</span>
      <span className="timing-value">{formatDuration(value)}</span>
    </div>
  );
}

export default App;
