import React from 'react';
import { motion } from 'framer-motion';
import { Shield, Fingerprint, Globe, ServerCrash, Database } from 'lucide-react';
import RiskGauge from './RiskGauge';
import MetricCard from './MetricCard';
import ExplanationList from './ExplanationList';

const Dashboard = ({ result }) => {
  if (!result) return null;

  const {
    input_domain,
    classification,
    severity,
    final_risk_score,
    explanation_details,
    raw_similarity,
    raw_intelligence,
    raw_content,
    raw_safe_browsing,
    raw_phishtank
  } = result;

  return (
    <motion.div 
      initial={{ opacity: 0, y: 30 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      className="max-w-6xl mx-auto px-4 md:px-6 pb-20"
    >
      {/* Header Info */}
      <div className="mb-12 text-center md:text-left flex flex-col md:flex-row md:items-end justify-between border-b border-white/[0.05] pb-6">
        <div>
          <h2 className="text-gray-400 text-sm tracking-widest uppercase font-bold mb-2">Analysis Results For</h2>
          <div className="text-3xl md:text-4xl font-extrabold text-white truncate max-w-full">
            {input_domain}
          </div>
        </div>
        {result.pipeline_metadata && (
        <div className="mt-4 md:mt-0 text-sm text-gray-500 font-mono bg-dark-800/80 px-4 py-2 rounded-lg border border-white/[0.05]">
            Processed in {(result.pipeline_metadata.total_ms / 1000).toFixed(2)}s
        </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* Left Column - Main Score */}
        <div className="lg:col-span-4 flex flex-col items-center justify-center glass-panel p-8">
          <RiskGauge 
            score={final_risk_score} 
            classification={classification} 
            severity={severity} 
          />
        </div>

        {/* Right Column - Metrics Grid */}
        <div className="lg:col-span-8 grid grid-cols-1 md:grid-cols-2 gap-4">
            <MetricCard 
                title="Google Safe Browsing" 
                icon={Shield} 
                statusColor={raw_safe_browsing?.is_disabled ? "text-gray-500" : (raw_safe_browsing?.is_safe ? "text-emerald-400" : "text-primary-500")}
            >
                {raw_safe_browsing?.is_disabled ? (
                    <span className="text-gray-500 font-medium">Disabled</span>
                ) : raw_safe_browsing?.is_safe ? (
                    <span className="text-emerald-400 font-medium">Safe - No threats detected</span>
                ) : (
                    <span className="text-primary-500 font-bold">Malicious - Threat detected!</span>
                )}
            </MetricCard>

            <MetricCard 
                title="PhishTank API" 
                icon={Database} 
                statusColor={raw_phishtank?.is_disabled ? "text-gray-500" : (raw_phishtank?.is_phishing ? "text-primary-500" : "text-emerald-400")}
            >
                {raw_phishtank?.is_disabled ? (
                    <span className="text-gray-500 font-medium">Disabled</span>
                ) : raw_phishtank?.is_phishing ? (
                    <span className="text-primary-500 font-bold">High Risk - Flagged Link</span>
                ) : (
                    <span className="text-emerald-400 font-medium">Safe - Not listed</span>
                )}
            </MetricCard>

            <MetricCard 
                title="Domain Similarity" 
                icon={Fingerprint} 
                value={`${Math.round((raw_similarity?.similarity_score || 0) * 100)}%`}
                statusColor="text-blue-400"
                detailRow
            >
                <div className="flex justify-between border-b border-white/[0.05] pb-2">
                    <span>Brand Detected:</span>
                    <span className="text-white font-medium">{raw_similarity?.brand_detected || 'None'}</span>
                </div>
                <div className="flex justify-between pt-1">
                    <span>Closest match:</span>
                    <span className="text-white font-medium">{raw_similarity?.closest_brand || 'N/A'}</span>
                </div>
            </MetricCard>

            <MetricCard 
                title="Intelligence" 
                icon={Globe} 
                statusColor="text-indigo-400"
                detailRow
            >
                <div className="flex justify-between border-b border-white/[0.05] pb-2">
                    <span>Age:</span>
                    <span className="text-white font-medium">{raw_intelligence?.domain_age_days ?? 'Unknown'} days</span>
                </div>
                <div className="flex justify-between pt-1">
                    <span>SSL Valid:</span>
                    <span className={raw_intelligence?.ssl_valid ? 'text-emerald-400' : 'text-primary-500'}>
                        {raw_intelligence?.ssl_valid ? 'Yes' : 'No'}
                    </span>
                </div>
            </MetricCard>

            <MetricCard 
                title="Page Content" 
                icon={ServerCrash} 
                statusColor="text-purple-400"
                detailRow
            >
                <div className="flex justify-between border-b border-white/[0.05] pb-2">
                    <span>Login Form:</span>
                    <span className={raw_content?.login_form_detected ? 'text-primary-500 font-bold' : 'text-white'}>
                        {raw_content?.login_form_detected ? 'Detected' : 'Not found'}
                    </span>
                </div>
                <div className="flex justify-between pt-1">
                    <span>Reachable:</span>
                    <span className={raw_content?.page_reachable ? 'text-emerald-400' : 'text-gray-500'}>
                        {raw_content?.page_reachable ? 'Yes' : 'No'}
                    </span>
                </div>
            </MetricCard>
        </div>

      </div>

      {/* Explanation Section */}
      <div className="mt-12 glass-panel p-6 md:p-8">
         <ExplanationList details={explanation_details} />
      </div>

    </motion.div>
  );
};

export default Dashboard;
