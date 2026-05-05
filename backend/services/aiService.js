import * as tf from '@tensorflow/tfjs';
import '@tensorflow/tfjs-backend-cpu';
import logger from '../utils/logger.js';

let aiModel;

export const initAIModel = async () => {
  try {
    aiModel = tf.sequential();
    aiModel.add(tf.layers.dense({ units: 10, activation: 'relu', inputShape: [5] }));
    aiModel.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));
    aiModel.compile({ optimizer: 'adam', loss: 'binaryCrossentropy' });
    logger.info("Enterprise AI Heuristics Engine initialized with TensorFlow.js");
  } catch (e) {
    logger.error(e, "Failed to initialize AI Model");
  }
};

export const getAnalyticalInsights = async () => {
  const stats = db.prepare('SELECT level, count(*) as count FROM logs GROUP BY level').all();
  const suspiciousCount = db.prepare('SELECT count(*) as count FROM logs WHERE suspicious=1').all()[0].count;
  
  return {
    distribution: stats,
    suspiciousCount,
    recommendation: suspiciousCount > 10 
      ? "Critical: High volume of suspicious events detected. Recommend immediate full system scan."
      : "Normal: System indicators within acceptable bounds."
  };
};
