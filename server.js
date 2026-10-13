/**
 * Wallet Platform API — single-file Express + MongoDB backend
 *
 * Render environment variables:
 *   MONGO_URI      MongoDB Atlas connection string
 *   JWT_SECRET     Long random secret
 *   PORT           Optional (Render supplies this)
 *   CLIENT_URL     Optional frontend origin
 *
 * Install dependencies:
 *   npm install express mongoose bcryptjs jsonwebtoken dotenv cors multer
 *
 * Notes:
 * - All money amounts are stored as numeric UGX amounts (not USD).
 * - Deposits remain pending until an admin approves them.
 * - Order returns are demo/platform rules, not guaranteed real-world earnings.
 * - Daily accrual catches up elapsed calendar days when an authenticated API
 *   request is made. For strict scheduled processing, add a persistent worker.
 */

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

const app = express();
app.set('trust proxy', 1);

const corsOptions = process.env.CLIENT_URL
  ? { origin: process.env.CLIENT_URL.split(',').map(s => s.trim()), credentials: true }
  : {};
app.use(cors(corsOptions));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
    if (!allowed.includes(file.mimetype)) {
      return cb(new Error('Receipt must be JPG, PNG, WEBP, or PDF.'));
    }
    cb(null, true);
  }
});

const UGX = value => Math.round(Number(value) || 0);
const isPositiveAmount = value => Number.isFinite(Number(value)) && Number(value) > 0;
const safeUser = user => ({
  id: user._id,
  name: user.name,
  email: user.email,
  phone: user.phone,
  role: user.role,
  status: user.status,
  referralCode: user.referralCode,
  walletBalance: user.walletBalance || 0,
  commissionBalance: user.commissionBalance || 0,
  currency: 'UGX'
});

// -----------------------------------------------------------------------------
// MODELS
// -----------------------------------------------------------------------------
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true, select: false },
  pin: { type: String, select: false },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  status: { type: String, enum: ['active', 'suspended'], default: 'active' },
  referralCode: { type: String, unique: true, sparse: true },
  referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  walletBalance: { type: Number, default: 0, min: 0 },
  commissionBalance: { type: Number, default: 0, min: 0 },
  resetPasswordToken: { type: String, select: false },
  resetPasswordExpire: { type: Date, select: false }
}, { timestamps: true });

userSchema.pre('save', async function () {
  if (this.isModified('password')) this.password = await bcrypt.hash(this.password, 10);
});
userSchema.methods.matchPassword = function (entered) {
  return bcrypt.compare(String(entered || ''), this.password);
};
userSchema.methods.setPin = async function (pin) {
  this.pin = await bcrypt.hash(String(pin), 10);
};
userSchema.methods.matchPin = function (entered) {
  return this.pin ? bcrypt.compare(String(entered || ''), this.pin) : Promise.resolve(false);
};
const User = mongoose.model('User', userSchema);

const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  planName: { type: String, required: true },
  amount: { type: Number, required: true, min: 1 },
  dailyReturnPercent: { type: Number, default: 0, min: 0 },
  durationDays: { type: Number, default: 30, min: 1 },
  daysAccrued: { type: Number, default: 0 },
  earnedCommission: { type: Number, default: 0 },
  lastAccruedAt: { type: Date, default: Date.now },
  status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' }
}, { timestamps: true });
const Order = mongoose.model('Order', orderSchema);

const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'commission', 'order', 'adjustment'], required: true },
  amount: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'completed'], default: 'pending' },
  method: String,
  accountDetails: String,
  note: String,
  network: String,
  transactionId: String,
  receiptData: Buffer,
  receiptContentType: String,
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  reviewedAt: Date
}, { timestamps: true });
const Transaction = mongoose.model('Transaction', transactionSchema);

const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, default: 'info' },
  isRead: { type: Boolean, default: false },
  readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
}, { timestamps: true });
const Notification = mongoose.model('Notification', notificationSchema);

const supportSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  subject: String,
  message: String,
  status: { type: String, enum: ['open', 'pending', 'closed'], default: 'open' },
  replies: [{
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    senderRole: String,
    message: String,
    createdAt: { type: Date, default: Date.now }
  }]
}, { timestamps: true });
const Support = mongoose.model('Support', supportSchema);

const settingsSchema = new mongoose.Schema({
  key: { type: String, default: 'global', unique: true },
  minDeposit: { type: Number, default: 1000 },
  minWithdrawal: { type: Number, default: 1000 },
  withdrawalFeePercent: { type: Number, default: 0 },
  referralLevel1Percent: { type: Number, default: 0 },
  referralLevel2Percent: { type: Number, default: 0 }
}, { timestamps: true });
const Settings = mongoose.model('Settings', settingsSchema);

async function getSettings() {
  let settings = await Settings.findOne({ key: 'global' });
  if (!settings) settings = await Settings.create({ key: 'global' });
  return settings;
}

async function notify(user, title, message, type = 'info') {
  return Notification.create({ user: user || null, title, message, type });
}

async function makeTransaction(data) {
  return Transaction.create(data);
}

// -----------------------------------------------------------------------------
// AUTH / COMMON MIDDLEWARE
// -----------------------------------------------------------------------------
const genToken = id => {
  if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET is not configured');
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' });
};
const protect = async (req, res, next) => {
  try {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'Please log in again (missing token).' });
    }
    const decoded = jwt.verify(header.slice(7), process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ success: false, message: 'User not found.' });
    if (user.status === 'suspended') return res.status(403).json({ success: false, message: 'Account suspended.' });
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid or expired login token.' });
  }
};
const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
  next();
};
async function genReferralCode(name) {
  const base = (name || 'USER').replace(/[^a-z]/gi, '').slice(0, 4).toUpperCase() || 'USER';
  for (let i = 0; i < 20; i++) {
    const code = `${base}${crypto.randomInt(1000, 10000)}`;
    if (!(await User.exists({ referralCode: code }))) return code;
  }
  return crypto.randomBytes(5).toString('hex').toUpperCase();
}

// Accrue each full elapsed calendar day once, capped at durationDays.
// The accrued amount goes into commissionBalance, not the spendable wallet.
async function accrueUserOrders(userId) {
  const orders = await Order.find({ user: userId, status: 'active' });
  const now = new Date();
  for (const order of orders) {
    const last = new Date(order.lastAccruedAt || order.createdAt);
    const elapsed = Math.max(0, Math.floor((now - last) / 86400000));
    const daysToAdd = Math.min(elapsed, Math.max(0, order.durationDays - order.daysAccrued));
    if (daysToAdd <= 0) {
      if (order.daysAccrued >= order.durationDays && order.status === 'active') {
        order.status = 'completed';
        await order.save();
      }
      continue;
    }
    const daily = UGX(order.amount * (order.dailyReturnPercent / 100));
    const earned = daily * daysToAdd;
    order.daysAccrued += daysToAdd;
    order.earnedCommission += earned;
    order.lastAccruedAt = new Date(last.getTime() + daysToAdd * 86400000);
    if (order.daysAccrued >= order.durationDays) order.status = 'completed';
    await order.save();

    if (earned > 0) {
      await User.updateOne({ _id: userId }, { $inc: { commissionBalance: earned } });
      await makeTransaction({
        user: userId, type: 'commission', amount: earned, status: 'completed',
        note: `Order ${order._id}: ${daysToAdd} day(s) accrued`
      });
      await notify(userId, 'Order commission added',
        `UGX ${earned.toLocaleString('en-UG')} commission was recorded for ${order.planName}.`, 'success');
    }
  }
}

// -----------------------------------------------------------------------------
// HEALTH / FRONTEND
// -----------------------------------------------------------------------------
app.get('/api/health', (req, res) => res.json({
  success: true, message: 'API is running', currency: 'UGX',
  database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
}));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// -----------------------------------------------------------------------------
// AUTH
// -----------------------------------------------------------------------------
app.post('/api/register', async (req, res, next) => {
  try {
    const { name, email, phone, password, referralCode } = req.body;
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ success: false, message: 'Name, email, phone and password are required.' });
    }
    const normalizedEmail = String(email).toLowerCase().trim();
    if (await User.findOne({ $or: [{ email: normalizedEmail }, { phone: String(phone).trim() }] })) {
      return res.status(409).json({ success: false, message: 'Email or phone already registered.' });
    }
    let referredBy = null;
    if (referralCode) {
      const referrer = await User.findOne({ referralCode: String(referralCode).trim().toUpperCase() });
      if (referrer) referredBy = referrer._id;
    }
    const user = await User.create({
      name: String(name).trim(), email: normalizedEmail, phone: String(phone).trim(),
      password, referredBy, referralCode: await genReferralCode(name)
    });
    await notify(user._id, 'Welcome', 'Your account has been created.', 'success');
    res.status(201).json({ success: true, token: genToken(user._id), user: safeUser(user) });
  } catch (err) { next(err); }
});

app.post('/api/login', async (req, res, next) => {
  try {
    const { emailOrPhone, password } = req.body;
    if (!emailOrPhone || !password) return res.status(400).json({ success: false, message: 'Email/phone and password required.' });
    const value = String(emailOrPhone).trim();
    const user = await User.findOne({ $or: [{ email: value.toLowerCase() }, { phone: value }] }).select('+password');
    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ success: false, message: 'Invalid credentials.' });
    }
    if (user.status === 'suspended') return res.status(403).json({ success: false, message: 'Account suspended.' });
    res.json({ success: true, token: genToken(user._id), user: safeUser(user) });
  } catch (err) { next(err); }
});

app.get('/api/users/me', protect, async (req, res) => {
  await accrueUserOrders(req.user._id);
  const user = await User.findById(req.user._id);
  res.json({ success: true, user: safeUser(user) });
});
app.put('/api/users/me', protect, async (req, res, next) => {
  try {
    const updates = {};
    if (req.body.name !== undefined) updates.name = String(req.body.name).trim();
    if (req.body.phone !== undefined) updates.phone = String(req.body.phone).trim();
    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true, runValidators: true });
    res.json({ success: true, user: safeUser(user) });
  } catch (err) { next(err); }
});
app.put('/api/auth/change-password', protect, async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('+password');
    if (!(await user.matchPassword(req.body.currentPassword))) return res.status(401).json({ success: false, message: 'Current password incorrect.' });
    if (!req.body.newPassword || String(req.body.newPassword).length < 8) return res.status(400).json({ success: false, message: 'New password must be at least 8 characters.' });
    user.password = req.body.newPassword;
    await user.save();
    res.json({ success: true, message: 'Password changed.' });
  } catch (err) { next(err); }
});
app.put('/api/auth/change-pin', protect, async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('+pin');
    if (user.pin && !(await user.matchPin(req.body.currentPin))) return res.status(401).json({ success: false, message: 'Current PIN incorrect.' });
    if (!/^\d{4,6}$/.test(String(req.body.newPin || ''))) return res.status(400).json({ success: false, message: 'PIN must be 4–6 digits.' });
    await user.setPin(req.body.newPin);
    await user.save();
    res.json({ success: true, message: 'PIN updated.' });
  } catch (err) { next(err); }
});
app.post('/api/auth/forgot-password', async (req, res, next) => {
  try {
    const user = await User.findOne({ email: String(req.body.email || '').toLowerCase() });
    // Do not reveal whether an account exists.
    if (!user) return res.json({ success: true, message: 'If the account exists, follow the password reset process.' });
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = crypto.createHash('sha256').update(rawToken).digest('hex');
    user.resetPasswordExpire = new Date(Date.now() + 30 * 60 * 1000);
    await user.save();
    // Demo only: connect a mail provider before production use.
    res.json({ success: true, message: 'Demo reset token generated.', resetToken: rawToken });
  } catch (err) { next(err); }
});
app.put('/api/auth/reset-password/:token', async (req, res, next) => {
  try {
    const hashed = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({
      resetPasswordToken: hashed, resetPasswordExpire: { $gt: new Date() }
    }).select('+resetPasswordToken +resetPasswordExpire');
    if (!user) return res.status(400).json({ success: false, message: 'Invalid or expired token.' });
    if (!req.body.password || String(req.body.password).length < 8) return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });
    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();
    res.json({ success: true, message: 'Password reset. Please log in.' });
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// DASHBOARD / TEAM
// -----------------------------------------------------------------------------
app.get('/api/users/dashboard', protect, async (req, res, next) => {
  try {
    await accrueUserOrders(req.user._id);
    const user = await User.findById(req.user._id);
    const activeOrders = await Order.countDocuments({ user: user._id, status: 'active' });
    const referralCount = await User.countDocuments({ referredBy: user._id });
    const totalOrders = await Order.countDocuments({ user: user._id });
    const data = {
      id: user._id, name: user.name, email: user.email, phone: user.phone,
      walletBalance: user.walletBalance || 0, commissionBalance: user.commissionBalance || 0,
      balance: user.walletBalance || 0, totalEarnings: user.commissionBalance || 0,
      activeOrders, totalOrders, referralCount, referralCode: user.referralCode || '',
      todayIncome: 0, totalInvestments: totalOrders, investments: activeOrders,
      referrals: referralCount, currency: 'UGX'
    };
    res.json({ success: true, data, dashboard: data, user: data });
  } catch (err) { next(err); }
});
app.get('/api/team', protect, async (req, res, next) => {
  try {
    const members = await User.find({ referredBy: req.user._id })
      .select('name email phone createdAt commissionBalance')
      .sort({ createdAt: -1 });
    const level1 = members.map(u => ({
      name: u.name, email: u.email, phone: u.phone,
      commission: u.commissionBalance || 0, level: 'Level 1', createdAt: u.createdAt
    }));
    res.json({ success: true, team: {
      referralCode: req.user.referralCode || '', referralLink: null,
      level1Count: level1.length, totalMembers: level1.length, activeMembers: level1.length,
      totalCommission: req.user.commissionBalance || 0, todayCommission: 0,
      level1, members: level1
    }});
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// DEPOSITS — both current frontend URL and wallet aliases
// Frontend FormData fields: amount, network, transactionId, optional receipt.
// -----------------------------------------------------------------------------
async function createDeposit(req, res, next) {
  try {
    const amount = Number(req.body.amount);
    const network = String(req.body.network || req.body.method || '').trim();
    const transactionId = String(req.body.transactionId || req.body.transaction_id || '').trim();
    const settings = await getSettings();
    if (!isPositiveAmount(amount) || amount < settings.minDeposit) {
      return res.status(400).json({ success: false, message: `Minimum deposit is UGX ${UGX(settings.minDeposit).toLocaleString('en-UG')}.` });
    }
    if (!network || !transactionId) return res.status(400).json({ success: false, message: 'Network and transaction ID are required.' });
    const doc = {
      user: req.user._id, type: 'deposit', amount: UGX(amount), method: network,
      network, transactionId, note: `Transaction ID: ${transactionId}`, status: 'pending'
    };
    if (req.file) {
      doc.receiptData = req.file.buffer;
      doc.receiptContentType = req.file.mimetype;
    }
    const deposit = await Transaction.create(doc);
    await notify(req.user._id, 'Deposit submitted', `Your UGX ${UGX(amount).toLocaleString('en-UG')} deposit is awaiting review.`, 'info');
    res.status(201).j
