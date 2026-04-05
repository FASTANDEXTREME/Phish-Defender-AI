import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, ChevronDown, ChevronUp, Clock, XCircle, Info } from 'lucide-react';

const AGENT_LABELS = {
  similarity: 'Domain Similarity',
  intelligence: 'Domain Intelligence',
  content: 'Page Content Analysis',
  safe_browsing: 'Google Safe Browsing',
  phishtank: 'PhishTank API',
  cross_reference: 'Cross-Reference Engine',
};

const DegradedResultsBanner = ({ pipelineMetadata }) => {
  const [expanded, setExpanded] = useState(false);

  if (!pipelineMetadata?.results_degraded) return null;

  const degradedAgents = pipelineMetadata.degraded_agents || [];
  const agentErrors = pipelineMetadata.agent_errors || {};
  const totalMs = pipelineMetadata.total_ms || 0;
  const deadlineExceeded = totalMs > 30000;

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="max-w-6xl mx-auto px-4 md:px-6 mb-6"
    >
      <div className="relative overflow-hidden rounded-2xl border border-amber-500/30 bg-amber-500/[0.06] backdrop-blur-xl">
        {/* Animated warning stripe */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-amber-400 to-transparent opacity-60" />

        {/* Main banner */}
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center justify-between px-5 py-4 text-left transition-colors hover:bg-amber-500/[0.04]"
        >
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20">
              <AlertTriangle className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className="text-amber-300 font-semibold text-sm tracking-wide">
                Degraded Results
              </p>
              <p className="text-amber-200/60 text-xs mt-0.5">
                {degradedAgents.length} agent{degradedAgents.length > 1 ? 's' : ''} timed out or failed — results may be less accurate
              </p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            {deadlineExceeded && (
              <span className="hidden sm:flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-mono">
                <Clock className="w-3 h-3" />
                <span>Deadline exceeded</span>
              </span>
            )}
            <span className="text-amber-400/60">
              {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
            </span>
          </div>
        </button>

        {/* Expandable details */}
        <AnimatePresence>
          {expanded && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3, ease: 'easeInOut' }}
              className="overflow-hidden"
            >
              <div className="px-5 pb-5 space-y-3 border-t border-amber-500/10 pt-4">
                {/* Header explanation */}
                <div className="flex items-start space-x-2 mb-4">
                  <Info className="w-4 h-4 text-amber-400/60 mt-0.5 flex-shrink-0" />
                  <p className="text-amber-200/50 text-xs leading-relaxed">
                    Some analysis agents could not complete their work within the time budget. 
                    The pipeline used fallback defaults for these agents, which means the risk 
                    score may be higher or lower than the true value. Re-analyzing may produce 
                    different results.
                  </p>
                </div>

                {/* Per-agent error cards */}
                {degradedAgents.map((agent) => (
                  <div
                    key={agent}
                    className="flex items-center justify-between px-4 py-3 rounded-xl bg-dark-800/60 border border-white/[0.05]"
                  >
                    <div className="flex items-center space-x-3">
                      <XCircle className="w-4 h-4 text-amber-500 flex-shrink-0" />
                      <span className="text-gray-300 text-sm font-medium">
                        {AGENT_LABELS[agent] || agent}
                      </span>
                    </div>
                    <span className="text-xs text-gray-500 font-mono max-w-[200px] sm:max-w-[300px] truncate text-right">
                      {agentErrors[agent] || 'Unknown error'}
                    </span>
                  </div>
                ))}

                {/* Timing info */}
                <div className="flex items-center justify-between px-4 py-2 text-xs text-gray-500">
                  <span>Total pipeline time</span>
                  <span className={`font-mono ${deadlineExceeded ? 'text-red-400' : 'text-gray-400'}`}>
                    {(totalMs / 1000).toFixed(2)}s
                    {deadlineExceeded && ' (exceeded 30s deadline)'}
                  </span>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
};

export default DegradedResultsBanner;
