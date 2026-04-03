import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Globe, Search, Database, CheckCircle2, Loader2, Fingerprint } from 'lucide-react';

const STEPS = [
  { id: 'sim', label: 'Domain Similarity Analysis', icon: Fingerprint, delay: 0 },
  { id: 'intel', label: 'Domain Intelligence Check', icon: Globe, delay: 1000 },
  { id: 'content', label: 'Website Content Inspection', icon: Database, delay: 2500 },
  { id: 'sb', label: 'Google Safe Browsing Verification', icon: Shield, delay: 3500 }
];

const ScanningAnimation = ({ isVisible }) => {
  const [activeStepIndex, setActiveStepIndex] = useState(0);

  useEffect(() => {
    if (!isVisible) {
      setActiveStepIndex(0);
      return;
    }

    const timeouts = STEPS.map((step, index) => {
      // Move to the current step after its delay
      return setTimeout(() => {
        setActiveStepIndex(index);
      }, step.delay);
    });

    return () => timeouts.forEach(clearTimeout);
  }, [isVisible]);

  if (!isVisible) return null;

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="max-w-2xl mx-auto px-6 mb-12"
    >
      <div className="glass-panel p-6 md:p-8 relative overflow-hidden">
        
        {/* Animated Scanning Line */}
        <motion.div 
          className="absolute left-0 right-0 h-0.5 bg-primary-500/50 shadow-glow-primary z-0"
          animate={{ top: ['0%', '100%', '0%'] }}
          transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
        />

        <div className="relative z-10">
          <div className="flex items-center space-x-3 mb-6">
            <div className="p-2 rounded-full bg-primary-500/10 animate-pulse">
                <Search className="w-5 h-5 text-primary-500" />
            </div>
            <h3 className="text-xl font-bold text-white tracking-wide">
              Analyzing Intelligence Data...
            </h3>
          </div>

          <div className="space-y-4">
            {STEPS.map((step, index) => {
              const isPast = activeStepIndex > index;
              const isCurrent = activeStepIndex === index;
              const isPending = activeStepIndex < index;
              
              const Icon = step.icon;

              let iconColor = "text-gray-600";
              let textColor = "text-gray-500";
              let StatusComponent = null;

              if (isPast) {
                 iconColor = "text-emerald-500";
                 textColor = "text-gray-300";
                 StatusComponent = <CheckCircle2 className="w-5 h-5 text-emerald-500" />;
              } else if (isCurrent) {
                 iconColor = "text-primary-500";
                 textColor = "text-white glow-text";
                 StatusComponent = <Loader2 className="w-5 h-5 text-primary-500 animate-spin" />;
              }

              return (
                <div key={step.id} className="flex items-center justify-between p-3 rounded-lg bg-dark-800/40 border border-white/[0.02]">
                  <div className={`flex items-center space-x-4 transition-colors duration-500 opacity-${isPending ? '50' : '100'}`}>
                    <Icon className={`w-5 h-5 transition-colors duration-500 ${iconColor}`} />
                    <span className={`font-medium transition-colors duration-500 ${textColor}`}>
                      {step.label}
                    </span>
                  </div>
                  <div className="flex-shrink-0">
                    {StatusComponent}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default ScanningAnimation;
