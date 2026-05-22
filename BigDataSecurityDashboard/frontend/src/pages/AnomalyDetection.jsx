import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { 
  FiEye, FiCpu, FiRefreshCw, FiAlertTriangle, 
  FiCheckCircle, FiInfo, FiTrendingUp, FiActivity, FiLayers 
} from 'react-icons/fi';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import { mlApi } from '../services/api';

const AnomalyDetection = () => {
  // Playground state
  const [testLine, setTestLine] = useState('');
  const [selectedClassifier, setSelectedClassifier] = useState('isolation_forest');
  const [prediction, setPrediction] = useState(null);
  const [predLoading, setPredLoading] = useState(false);
  const [predError, setPredError] = useState(null);

  // Retrain state
  const [retraining, setRetraining] = useState(false);
  const [trainSuccess, setTrainSuccess] = useState(null);
  
  // Model summaries
  const [summary, setSummary] = useState({
    total_logs: 0,
    total_anomalies: 0,
    anomaly_rate: 0,
    high_severity_alerts: 0,
    critical_severity_alerts: 0
  });
  const [summaryLoading, setSummaryLoading] = useState(true);

  const fetchSummary = async () => {
    try {
      const data = await mlApi.getSummary();
      setSummary(data);
      setSummaryLoading(false);
    } catch (err) {
      console.error("Failed to load ML summary:", err);
      setSummaryLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary();
  }, []);

  const handlePredict = async (e) => {
    e.preventDefault();
    if (!testLine.trim()) return;

    setPredLoading(true);
    setPredError(null);
    setPrediction(null);

    try {
      const res = await mlApi.predictSingle(testLine, selectedClassifier);
      setPrediction(res);
    } catch (err) {
      setPredError(err.response?.data?.detail || "Parsing error. Ensure log format matches Apache combined patterns.");
    } finally {
      setPredLoading(false);
    }
  };

  const handleRetrain = async () => {
    setRetraining(true);
    setTrainSuccess(null);
    try {
      const res = await mlApi.retrainModel();
      setTrainSuccess(res.message);
      fetchSummary();
    } catch (err) {
      console.error(err);
      alert("Failed to retrain model.");
    } finally {
      setRetraining(false);
    }
  };

  const fillSample = (type) => {
    const samples = {
      sqli: '185.220.101.5 - - [21/May/2026:10:00:00 +0000] "GET /api/users?id=1%20UNION%20SELECT%20NULL,username,password%20FROM%20users-- HTTP/1.1" 500 2048',
      traversal: '82.102.23.45 - - [21/May/2026:10:01:00 +0000] "GET /static/../../etc/passwd HTTP/1.1" 400 512',
      normal: '122.164.48.9 - - [21/May/2026:10:02:00 +0000] "GET /index.html HTTP/1.1" 200 4096'
    };
    setTestLine(samples[type]);
  };

  const classifiers = [
    { id: 'isolation_forest', name: 'Isolation Forest', desc: 'Unsupervised tree anomaly partitioner (Ideal for zero-day outliers)', color: 'text-cyberGreen', border: 'border-cyberGreen/25' },
    { id: 'random_forest', name: 'Random Forest', desc: 'Supervised parallel multi-decision trees voting (Strong correlation mapping)', color: 'text-cyberBlue', border: 'border-cyberBlue/25' },
    { id: 'logistic_regression', name: 'Logistic Regression', desc: 'Supervised probability-based linear classification (High-speed parsing)', color: 'text-cyberYellow', border: 'border-cyberYellow/25' },
    { id: 'gradient_boosting', name: 'Gradient Boosting', desc: 'Supervised sequential boosting trees (High precision classification)', color: 'text-cyberRed', border: 'border-cyberRed/25' }
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-darkBg text-gray-200">
      <Sidebar />
      
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header title="MACHINE LEARNING ANOMALY DETECTION ENGINE" />
        
        <main className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
          {/* Models Stats & Training Trigger */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Classifiers summary */}
            <div className="lg:col-span-2 rounded-xl border border-cardBorder bg-[#0C111D] p-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono mb-4 flex items-center gap-2">
                <FiCpu className="text-cyberGreen" />
                Active Classifiers Inventory & Specs
              </h3>

              {summaryLoading ? (
                <div className="flex h-24 items-center justify-center text-cyberGreen">
                  <span className="h-6 w-6 animate-spin rounded-full border-2 border-cardBorder border-t-cyberGreen"></span>
                </div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  {classifiers.map((c) => (
                    <div key={c.id} className="bg-[#05070C] p-3 rounded border border-cardBorder flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between mb-1">
                          <span className={`font-bold ${c.color}`}>{c.name}</span>
                          <span className="text-[9px] bg-cardBorder px-1.5 py-0.5 rounded text-gray-400 font-semibold uppercase">ACTIVE</span>
                        </div>
                        <p className="text-[10px] text-gray-500">{c.desc}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Model control */}
            <div className="rounded-xl border border-cardBorder bg-[#0C111D] p-5 flex flex-col justify-between">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono mb-2 flex items-center gap-2">
                  <FiRefreshCw className="text-cyberBlue" />
                  Model Pipeline Training
                </h3>
                <p className="text-xs text-gray-400">
                  Refits the vectorizer and trains all 4 classifiers separately (Isolation Forest, Random Forest, Logistic Regression, and Gradient Boosting) on all parsed files.
                </p>
              </div>

              <div className="mt-4 space-y-2">
                {trainSuccess && (
                  <div className="rounded border border-cyberGreen/20 bg-cyberGreen/5 p-2 text-[10px] text-cyberGreen font-mono">
                    {trainSuccess}
                  </div>
                )}
                <button
                  onClick={handleRetrain}
                  disabled={retraining}
                  className="w-full py-2.5 rounded bg-cyberBlue text-darkBg font-bold text-xs uppercase tracking-wider shadow-glowBlue hover:bg-cyberBlue/90 transition disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {retraining ? (
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-darkBg border-t-transparent"></span>
                  ) : (
                    <>
                      <FiRefreshCw />
                      <span>Retrain Classifiers</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Playground Sandbox */}
          <div className="rounded-xl border border-cardBorder bg-[#0C111D] p-5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono mb-4 flex items-center gap-2">
              <FiEye className="text-cyberYellow" />
              ML Prediction Sandbox & Classifier Comparison
            </h3>

            {/* Pasting Box */}
            <form onSubmit={handlePredict} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="md:col-span-3">
                  <label className="block text-[10px] uppercase font-mono tracking-wider text-gray-500 mb-1.5">
                    Paste Raw Apache Combined Log Line
                  </label>
                  <textarea
                    rows="3"
                    value={testLine}
                    onChange={(e) => setTestLine(e.target.value)}
                    placeholder='127.0.0.1 - - [21/May/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
                    className="w-full rounded-lg border border-cardBorder bg-[#05070C] p-3 text-xs font-mono text-white placeholder-gray-700 outline-none focus:border-cyberGreen"
                  />
                </div>
                
                <div>
                  <label className="block text-[10px] uppercase font-mono tracking-wider text-gray-500 mb-1.5">
                    Select Active Classifier
                  </label>
                  <div className="flex flex-col gap-2">
                    {classifiers.map((clf) => (
                      <label 
                        key={clf.id} 
                        className={`flex items-center gap-2 p-2.5 rounded-lg border bg-[#05070C] text-[11px] font-mono cursor-pointer transition-all ${
                          selectedClassifier === clf.id 
                            ? 'border-cyberGreen text-white shadow-glowGreen/5 bg-cardBorder/30' 
                            : 'border-cardBorder text-gray-500 hover:border-gray-700 hover:text-gray-300'
                        }`}
                      >
                        <input
                          type="radio"
                          name="classifier"
                          value={clf.id}
                          checked={selectedClassifier === clf.id}
                          onChange={(e) => setSelectedClassifier(e.target.value)}
                          className="accent-cyberGreen h-3.5 w-3.5 flex-shrink-0"
                        />
                        <span className="truncate">{clf.name}</span>
                      </label>
                    ))}
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-cardBorder/40 pt-4">
                {/* Samples */}
                <div className="flex gap-2">
                  <button 
                    type="button" 
                    onClick={() => fillSample('normal')}
                    className="rounded bg-cardBorder/50 px-3 py-1.5 text-[10px] font-mono text-cyberGreen hover:bg-cardBorder"
                  >
                    + Sample Normal
                  </button>
                  <button 
                    type="button" 
                    onClick={() => fillSample('sqli')}
                    className="rounded bg-cardBorder/50 px-3 py-1.5 text-[10px] font-mono text-cyberRed hover:bg-cardBorder"
                  >
                    + Sample SQLi
                  </button>
                  <button 
                    type="button" 
                    onClick={() => fillSample('traversal')}
                    className="rounded bg-cardBorder/50 px-3 py-1.5 text-[10px] font-mono text-cyberYellow hover:bg-cardBorder"
                  >
                    + Sample Directory Traversal
                  </button>
                </div>

                <button
                  type="submit"
                  disabled={predLoading}
                  className="rounded bg-cyberGreen px-6 py-2 text-xs font-bold text-darkBg uppercase font-sans tracking-widest shadow-glowGreen hover:bg-cyberGreen/90 disabled:opacity-50"
                >
                  {predLoading ? "Analyzing..." : "RUN CLASSIFIER"}
                </button>
              </div>
            </form>

            {/* Prediction Output */}
            {predError && (
              <div className="mt-4 rounded-lg border border-cyberRed/20 bg-cyberRed/5 p-4 text-xs font-mono text-cyberRed">
                Error: {predError}
              </div>
            )}

            {prediction && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-6 rounded-lg border border-cardBorder bg-cardBg p-5 space-y-5"
              >
                {/* Active Classifier Verdict Banner */}
                <div className="flex items-center justify-between border-b border-cardBorder/50 pb-3">
                  <span className="text-xs font-bold text-white uppercase font-mono flex items-center gap-2">
                    <FiLayers className="text-cyberGreen" />
                    Active Result: {classifiers.find(c => c.id === selectedClassifier)?.name}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    prediction.prediction === 'Anomaly'
                      ? 'bg-cyberRed/20 text-cyberRed border border-cyberRed/30 animate-pulse'
                      : 'bg-cyberGreen/20 text-cyberGreen border border-cyberGreen/30'
                  }`}>
                    {prediction.prediction}
                  </span>
                </div>

                {/* Score details */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-xs">
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase">Anomaly Score</span>
                    <p className="mt-1 font-bold text-white">{(prediction.anomaly_score * 100).toFixed(1)}%</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase">Threat Severity</span>
                    <p className="mt-1 font-bold text-white">{prediction.threat_severity}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase">Rule Verdict</span>
                    <p className="mt-1 font-bold text-white">{prediction.threat_type}</p>
                  </div>
                  <div>
                    <span className="text-[10px] text-gray-500 uppercase">Detector Confidence</span>
                    <p className="mt-1 font-bold text-cyberGreen">
                      {prediction.anomaly_score > 0.65 ? 'HIGH' : 'LOW'}
                    </p>
                  </div>
                </div>

                <div className="p-3 rounded bg-[#05070C] border border-cardBorder flex items-start gap-2.5">
                  <FiInfo className="text-cyberBlue mt-0.5 flex-shrink-0 text-sm" />
                  <div className="text-xs text-gray-400 font-mono">
                    <span className="font-semibold text-white">Details: </span>
                    {prediction.details}
                  </div>
                </div>

                {/* Classifier Comparisons section */}
                {prediction.all_predictions && (
                  <div className="border-t border-cardBorder/40 pt-4 space-y-3">
                    <h4 className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-1.5">
                      <FiTrendingUp className="text-cyberBlue" />
                      Classifiers Audit Comparison Feed
                    </h4>
                    
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      {Object.keys(prediction.all_predictions).map((key) => {
                        const clfData = prediction.all_predictions[key];
                        const clfMeta = classifiers.find(c => c.id === key);
                        const isAnom = clfData.prediction === 'Anomaly';
                        const isActive = selectedClassifier === key;
                        
                        return (
                          <div 
                            key={key} 
                            className={`p-3 rounded-lg border text-xs font-mono relative transition-all ${
                              isActive 
                                ? 'border-cyberGreen/45 bg-[#0C111D] shadow-glowGreen/5' 
                                : 'border-cardBorder bg-[#05070C]'
                            }`}
                          >
                            {isActive && (
                              <span className="absolute top-2 right-2 text-[8px] bg-cyberGreen/20 text-cyberGreen px-1 rounded font-bold uppercase">
                                ACTIVE
                              </span>
                            )}
                            <p className="font-bold text-gray-300 text-[11px] mb-1">{clfMeta?.name}</p>
                            
                            <div className="flex items-center justify-between text-[10px] mt-2 mb-1.5">
                              <span className="text-gray-500">VERDICT:</span>
                              <span className={isAnom ? 'text-cyberRed font-bold' : 'text-cyberGreen font-bold'}>
                                {clfData.prediction}
                              </span>
                            </div>

                            <div className="space-y-1">
                              <div className="flex items-center justify-between text-[10px]">
                                <span className="text-gray-500">SCORE:</span>
                                <span className="text-white font-bold">{(clfData.score * 100).toFixed(1)}%</span>
                              </div>
                              {/* Small health bar progress */}
                              <div className="h-1 w-full bg-cardBorder rounded overflow-hidden">
                                <div 
                                  className={`h-full ${isAnom ? 'bg-cyberRed' : 'bg-cyberGreen'}`} 
                                  style={{ width: `${clfData.score * 100}%` }}
                                ></div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </motion.div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
};

export default AnomalyDetection;
