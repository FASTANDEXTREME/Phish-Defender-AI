import React, { useEffect, useState } from 'react';
import { motion } from 'framer-motion';

const getSeverityColor = (severity) => {
    switch(severity) {
        case 'CRITICAL': return '#ff2e2e'; // Primary Red
        case 'HIGH': return '#f97316'; // Orange
        case 'MEDIUM': return '#eab308'; // Yellow
        case 'LOW': return '#3b82f6'; // Blue
        case 'INFO':
        case 'SAFE': return '#10b981'; // Green
        default: return '#6b7280';
    }
}

const getLabelColor = (label) => {
    if (label === 'PHISHING') return '#ff2e2e';
    if (label === 'SUSPICIOUS') return '#eab308';
    if (label === 'SAFE') return '#10b981';
    return '#6b7280';
}

const RiskGauge = ({ score, classification, severity }) => {
    const [animatedScore, setAnimatedScore] = useState(0);
    const normalizedScore = Math.max(0, Math.min(100, Math.round(score * 100)));
    
    // SVG Settings
    const size = 260;
    const strokeWidth = 16;
    const center = size / 2;
    const radius = center - strokeWidth;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (animatedScore / 100) * circumference;

    useEffect(() => {
        const timeout = setTimeout(() => {
            setAnimatedScore(normalizedScore);
        }, 100);
        return () => clearTimeout(timeout);
    }, [normalizedScore]);

    const color = getLabelColor(classification);

    return (
        <div className="flex flex-col items-center justify-center">
            {/* SVG Constraint container to perfectly center text inside ring */}
            <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
                {/* Glow effect behind the ring */}
                <div 
                    className="absolute w-40 h-40 rounded-full blur-[50px] opacity-20 pointer-events-none" 
                    style={{ backgroundColor: color }} 
                />

                <svg width={size} height={size} className="absolute transform -rotate-90">
                    {/* Background Ring */}
                    <circle
                        cx={center}
                        cy={center}
                        r={radius}
                        fill="transparent"
                        stroke="#252525"
                        strokeWidth={strokeWidth}
                        strokeLinecap="round"
                    />
                    
                    {/* Progress Ring */}
                    <motion.circle
                        cx={center}
                        cy={center}
                        r={radius}
                        fill="transparent"
                        stroke={color}
                        strokeWidth={strokeWidth}
                        strokeLinecap="round"
                        strokeDasharray={circumference}
                        animate={{ strokeDashoffset: offset }}
                        transition={{ duration: 1.5, ease: "easeOut" }}
                    />
                </svg>

                {/* Inner Content */}
                <div className="absolute flex flex-col items-center justify-center text-center">
                    <span className="text-6xl font-black text-white glow-text" style={{ textShadow: `0 0 20px ${color}80` }}>
                        {animatedScore}
                    </span>
                    <span className="text-sm text-gray-400 font-semibold tracking-widest uppercase mt-1">
                        Risk Score
                    </span>
                </div>
            </div>

            {/* Badges below */}
            <div className="mt-8 flex space-x-4">
                <div 
                    className="px-4 py-2 rounded-lg font-bold tracking-wider text-sm border"
                    style={{ 
                        backgroundColor: `${color}15`, 
                        color: color, 
                        borderColor: `${color}40`,
                        boxShadow: `0 0 15px ${color}20` 
                    }}
                >
                    {classification}
                </div>
                
                <div 
                    className="px-4 py-2 rounded-lg font-bold tracking-wider text-sm border bg-dark-800"
                    style={{ 
                        borderColor: '#ffffff1a',
                        color: getSeverityColor(severity)
                    }}
                >
                    {severity} SEVERITY
                </div>
            </div>
        </div>
    );
};

export default RiskGauge;
