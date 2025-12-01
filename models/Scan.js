const mongoose = require('mongoose');

const scanSchema = new mongoose.Schema({
  type: { 
    type: String, 
    required: true, 
    enum: ['CONTRACT', 'TRANSACTION', 'WALLET'] 
  },
  // Common fields
  target: { type: String, required: true }, // Address or Hash
  riskScore: { type: Number, required: true },
  riskLevel: { 
    type: String, 
    required: true,
    enum: ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
  },
  timestamp: { type: Date, default: Date.now },
  
  // Dynamic result object based on scan type
  result: { type: Object, required: true }
});

module.exports = mongoose.model('Scan', scanSchema);