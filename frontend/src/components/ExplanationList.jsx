import React from 'react';
import { AlertCircle, AlertTriangle, Info, CheckCircle2 } from 'lucide-react';
import { motion } from 'framer-motion';

const getImpactData = (impact) => {
    switch(impact) {
        case 'critical': 
            return { color: 'text-primary-500', bg: 'bg-primary-500/10', border: 'border-primary-500/20', Icon: AlertCircle };
        case 'high': 
            return { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/20', Icon: AlertTriangle };
        case 'medium': 
            return { color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', Icon: AlertTriangle };
        case 'low': 
            return { color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/20', Icon: Info };
        default: 
            return { color: 'text-emerald-400', bg: 'bg-emerald-400/10', border: 'border-emerald-400/20', Icon: CheckCircle2 };
    }
}

const ExplanationList = ({ details }) => {
    if (!details || details.length === 0) return null;

    return (
        <div className="space-y-4">
            <h3 className="text-xl font-bold text-white mb-6 border-b border-white/[0.05] pb-4">
                Risk Factor Breakdown
            </h3>
            <div className="grid gap-3">
                {details.map((item, index) => {
                    const impactData = getImpactData(item.impact);
                    const { Icon } = impactData;
                    
                    return (
                        <motion.div 
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            transition={{ duration: 0.4, delay: index * 0.1 }}
                            key={index} 
                            className={`flex items-start space-x-4 p-4 rounded-xl border ${impactData.bg} ${impactData.border} backdrop-blur-sm`}
                        >
                            <div className={`mt-0.5 ${impactData.color}`}>
                                <Icon className="w-5 h-5" />
                            </div>
                            <div className="flex-1">
                                <p className="text-gray-200 text-sm md:text-base leading-relaxed">
                                    {item.signal}
                                </p>
                                <div className="mt-2 flex items-center space-x-2">
                                    <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded border ${impactData.border} ${impactData.color} bg-black/40`}>
                                        {item.category.replace('_', ' ')}
                                    </span>
                                    <span className="text-[10px] text-gray-500 uppercase font-semibold">
                                        Impact: {item.impact}
                                    </span>
                                </div>
                            </div>
                        </motion.div>
                    );
                })}
            </div>
        </div>
    );
};

export default ExplanationList;
