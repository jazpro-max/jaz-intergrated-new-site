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
    res.status(201).json({ success: true, message: 'Deposit submitted successfully. Awaiting approval.', transaction: {
      id: deposit._id, amount: deposit.amount, status: deposit.status, createdAt: deposit.createdAt
    }});
  } catch (err) { next(err); }
}
app.post('/api/deposit', protect, upload.single('receipt'), createDeposit);
app.post('/api/wallet/deposit', protect, upload.single('receipt'), createDeposit);

async function depositHistory(req, res, next) {
  try {
    const deposits = await Transaction.find({ user: req.user._id, type: 'deposit' })
      .select('-receiptData').sort({ createdAt: -1 });
    res.json(deposits.map(item => ({
      id: item._id, amount: item.amount, network: item.network || item.method || '',
      transaction_id: item.transactionId || '', created_at: item.createdAt,
      status: item.status, note: item.note
    })));
  } catch (err) { next(err); }
}
app.get('/api/deposits/history', protect, depositHistory);
app.get('/api/wallet/deposits', protect, async (req, res, next) => {
  try {
    const deposits = await Transaction.find({ user: req.user._id, type: 'deposit' }).select('-receiptData').sort({ createdAt: -1 });
    res.json({ success: true, deposits });
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// WITHDRAWALS — requests remain pending; admin approval makes the balance change.
// -----------------------------------------------------------------------------
async function createWithdrawal(req, res, next) {
  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || req.body.network || '').trim();
    const accountDetails = String(req.body.accountDetails || '').trim();
    const pin = req.body.pin;
    const settings = await getSettings();
    if (!isPositiveAmount(amount) || amount < settings.minWithdrawal) {
      return res.status(400).json({ success: false, message: `Minimum withdrawal is UGX ${UGX(settings.minWithdrawal).toLocaleString('en-UG')}.` });
    }
    if (!method || !accountDetails) return res.status(400).json({ success: false, message: 'Withdrawal method and account details are required.' });
    const user = await User.findById(req.user._id).select('+pin');
    if (!(await user.matchPin(pin))) return res.status(401).json({ success: false, message: 'Incorrect PIN.' });
    if (user.walletBalance < amount) return res.status(400).json({ success: false, message: 'Insufficient wallet balance.' });
    const tx = await Transaction.create({
      user: user._id, type: 'withdrawal', amount: UGX(amount),
      fee: UGX(amount * settings.withdrawalFeePercent / 100),
      method, accountDetails, status: 'pending'
    });
    await notify(user._id, 'Withdrawal requested', `Your UGX ${UGX(amount).toLocaleString('en-UG')} withdrawal is awaiting review.`);
    res.status(201).json({ success: true, message: 'Withdrawal request submitted.', transaction: tx });
  } catch (err) { next(err); }
}
app.post('/api/wallet/withdraw', protect, createWithdrawal);
app.post('/api/withdraw', protect, createWithdrawal);
app.get('/api/wallet/withdrawals', protect, async (req, res, next) => {
  try {
    const withdrawals = await Transaction.find({ user: req.user._id, type: 'withdrawal' }).sort({ createdAt: -1 });
    res.json({ success: true, withdrawals });
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// ORDERS / COMMISSIONS
// -----------------------------------------------------------------------------
app.post('/api/orders', protect, async (req, res, next) => {
  try {
    const planName = String(req.body.planName || 'Standard plan').trim();
    const amount = Number(req.body.amount);
    const dailyReturnPercent = Number(req.body.dailyReturnPercent || 0);
    const durationDays = Number(req.body.durationDays || 30);
    if (!isPositiveAmount(amount) || !Number.isFinite(dailyReturnPercent) || dailyReturnPercent < 0 ||
        !Number.isInteger(durationDays) || durationDays < 1 || durationDays > 3650) {
      return res.status(400).json({ success: false, message: 'Invalid amount, daily percentage or duration.' });
    }
    if (dailyReturnPercent > 100) return res.status(400).json({ success: false, message: 'Daily percentage is outside the allowed demo range.' });
    const user = await User.findById(req.user._id).select('+pin');
    if (req.body.pin && !(await user.matchPin(req.body.pin))) return res.status(401).json({ success: false, message: 'Incorrect PIN.' });
    if (user.walletBalance < amount) return res.status(400).json({ success: false, message: 'Insufficient wallet balance.' });

    user.walletBalance -= UGX(amount);
    await user.save();
    const order = await Order.create({
      user: user._id, planName, amount: UGX(amount), dailyReturnPercent,
      durationDays, daysAccrued: 0, earnedCommission: 0, lastAccruedAt: new Date(), status: 'active'
    });
    await makeTransaction({ user: user._id, type: 'order', amount: UGX(amount), status: 'completed', note: `Order: ${planName}` });
    await notify(user._id, 'Order created', `Your ${planName} order has started for UGX ${UGX(amount).toLocaleString('en-UG')}.`);
    res.status(201).json({ success: true, order, walletBalance: user.walletBalance, currency: 'UGX' });
  } catch (err) { next(err); }
});
app.get('/api/orders', protect, async (req, res, next) => {
  try {
    await accrueUserOrders(req.user._id);
    const orders = await Order.find({ user: req.user._id }).sort({ createdAt: -1 });
    res.json({ success: true, orders, currency: 'UGX' });
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// TRANSACTIONS — one unified history plus legacy-friendly aliases
// -----------------------------------------------------------------------------
app.get('/api/transactions', protect, async (req, res, next) => {
  try {
    await accrueUserOrders(req.user._id);
    const filter = { user: req.user._id };
    if (req.query.type) filter.type = String(req.query.type);
    const transactions = await Transaction.find(filter).select('-receiptData').sort({ createdAt: -1 });
    res.json({ success: true, transactions, records: transactions, currency: 'UGX' });
  } catch (err) { next(err); }
});
app.get('/api/transactions/history', protect, async (req, res, next) => {
  try {
    const transactions = await Transaction.find({ user: req.user._id }).select('-receiptData').sort({ createdAt: -1 });
    res.json({ success: true, transactions, records: transactions, currency: 'UGX' });
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// NOTIFICATIONS — listing, single-read and mark-all-read
// -----------------------------------------------------------------------------
app.get('/api/notifications', protect, async (req, res, next) => {
  try {
    const notes = await Notification.find({ $or: [{ user: req.user._id }, { user: null }] })
      .sort({ createdAt: -1 }).limit(100);
    res.json({ success: true, notifications: notes.map(n => ({
      id: n._id, title: n.title, message: n.message, type: n.type,
      isRead: n.user ? n.isRead : n.readBy.some(id => id.equals(req.user._id)),
      createdAt: n.createdAt
    }))});
  } catch (err) { next(err); }
});
app.put('/api/notifications/:id/read', protect, async (req, res, next) => {
  try {
    const note = await Notification.findById(req.params.id);
    if (!note) return res.status(404).json({ success: false, message: 'Notification not found.' });
    if (note.user && !note.user.equals(req.user._id)) return res.status(403).json({ success: false, message: 'Not authorized.' });
    if (note.user) note.isRead = true;
    else if (!note.readBy.some(id => id.equals(req.user._id))) note.readBy.push(req.user._id);
    await note.save();
    res.json({ success: true, message: 'Notification marked as read.' });
  } catch (err) { next(err); }
});
app.put('/api/notifications/read-all', protect, async (req, res, next) => {
  try {
    await Notification.updateMany({ user: req.user._id, isRead: false }, { $set: { isRead: true } });
    await Notification.updateMany({ user: null, readBy: { $ne: req.user._id } }, { $addToSet: { readBy: req.user._id } });
    res.json({ success: true, message: 'Notifications marked as read.' });
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// SUPPORT
// -----------------------------------------------------------------------------
app.post('/api/support', protect, async (req, res, next) => {
  try {
    if (!req.body.subject || !req.body.message) return res.status(400).json({ success: false, message: 'Subject and message are required.' });
    const ticket = await Support.create({ user: req.user._id, subject: req.body.subject, message: req.body.message });
    res.status(201).json({ success: true, ticket });
  } catch (err) { next(err); }
});
app.get('/api/support', protect, async (req, res, next) => {
  try {
    res.json({ success: true, tickets: await Support.find({ user: req.user._id }).sort({ createdAt: -1 }) });
  } catch (err) { next(err); }
});
app.post('/api/support/:id/reply', protect, async (req, res, next) => {
  try {
    const ticket = await Support.findById(req.params.id);
    if (!ticket) return res.status(404).json({ success: false, message: 'Ticket not found.' });
    if (!ticket.user.equals(req.user._id) && req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Not authorized.' });
    if (!req.body.message) return res.status(400).json({ success: false, message: 'Reply message is required.' });
    ticket.replies.push({ sender: req.user._id, senderRole: req.user.role, message: String(req.body.message) });
    await ticket.save();
    res.json({ success: true, ticket });
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// ADMIN — review deposits/withdrawals and create broadcast notifications
// To make a user admin, update that user's role to "admin" securely in Atlas.
// -----------------------------------------------------------------------------
app.get('/api/admin/transactions', protect, adminOnly, async (req, res, next) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.type) filter.type = req.query.type;
    const transactions = await Transaction.find(filter).select('-receiptData').populate('user', 'name email phone').sort({ createdAt: -1 }).limit(500);
    res.json({ success: true, transactions, currency: 'UGX' });
  } catch (err) { next(err); }
});
app.get('/api/admin/transactions/:id/receipt', protect, adminOnly, async (req, res, next) => {
  try {
    const tx = await Transaction.findById(req.params.id).select('+receiptData');
    if (!tx || !tx.receiptData) return res.status(404).json({ success: false, message: 'Receipt not found.' });
    res.type(tx.receiptContentType || 'application/octet-stream').send(tx.receiptData);
  } catch (err) { next(err); }
});
app.put('/api/admin/transactions/:id/review', protect, adminOnly, async (req, res, next) => {
  const session = await mongoose.startSession();
  try {
    const decision = String(req.body.status || '').toLowerCase();
    if (!['approved', 'rejected'].includes(decision)) {
      return res.status(400).json({ success: false, message: 'Status must be approved or rejected.' });
    }
    let response;
    await session.withTransaction(async () => {
      const tx = await Transaction.findById(req.params.id).session(session);
      if (!tx) throw Object.assign(new Error('Transaction not found.'), { statusCode: 404 });
      if (!['deposit', 'withdrawal'].includes(tx.type)) throw Object.assign(new Error('Only deposits and withdrawals can be reviewed.'), { statusCode: 400 });
      if (tx.status !== 'pending') throw Object.assign(new Error('This transaction has already been reviewed.'), { statusCode: 409 });

      tx.status = decision;
      tx.reviewedBy = req.user._id;
      tx.reviewedAt = new Date();

      if (tx.type === 'deposit' && decision === 'approved') {
        await User.updateOne({ _id: tx.user }, { $inc: { walletBalance: tx.amount } }, { session });
      }
      if (tx.type === 'withdrawal' && decision === 'approved') {
        const user = await User.findById(tx.user).session(session);
        const total = tx.amount + (tx.fee || 0);
        if (!user || user.walletBalance < total) throw Object.assign(new Error('User no longer has enough wallet balance.'), { statusCode: 409 });
        user.walletBalance -= total;
        await user.save({ session });
      }
      await tx.save({ session });
      response = { id: tx._id, type: tx.type, amount: tx.amount, status: tx.status, user: tx.user };
    });
    await notify(response.user, `${response.type} ${decision}`, `Your ${response.type} of UGX ${UGX(response.amount).toLocaleString('en-UG')} was ${decision}.`, decision === 'approved' ? 'success' : 'warning');
    res.json({ success: true, message: `Transaction ${decision}.`, transaction: response });
  } catch (err) {
    res.status(err.statusCode || 500).json({ success: false, message: err.message || 'Could not review transaction.' });
  } finally {
    await session.endSession();
  }
});
app.post('/api/admin/notifications', protect, adminOnly, async (req, res, next) => {
  try {
    if (!req.body.title || !req.body.message) return res.status(400).json({ success: false, message: 'Title and message required.' });
    const note = await notify(null, String(req.body.title), String(req.body.message), String(req.body.type || 'info'));
    res.status(201).json({ success: true, notification: note });
  } catch (err) { next(err); }
});
app.get('/api/admin/users', protect, adminOnly, async (req, res, next) => {
  try {
    const users = await User.find().select('name email phone role status walletBalance commissionBalance createdAt').sort({ createdAt: -1 }).limit(500);
    res.json({ success: true, users });
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// SETTINGS (admin read/update)
// -----------------------------------------------------------------------------
app.get('/api/settings', protect, async (req, res, next) => {
  try {
    const s = await getSettings();
    res.json({ success: true, settings: {
      minDeposit: s.minDeposit, minWithdrawal: s.minWithdrawal,
      withdrawalFeePercent: s.withdrawalFeePercent, currency: 'UGX'
    }});
  } catch (err) { next(err); }
});
app.put('/api/admin/settings', protect, adminOnly, async (req, res, next) => {
  try {
    const allowed = ['minDeposit', 'minWithdrawal', 'withdrawalFeePercent', 'referralLevel1Percent', 'referralLevel2Percent'];
    const updates = {};
    for (const key of allowed) {
      if (req.body[key] !== undefined) {
        const n = Number(req.body[key]);
        if (!Number.isFinite(n) || n < 0) return res.status(400).json({ success: false, message: `Invalid ${key}.` });
        updates[key] = n;
      }
    }
    const settings = await Settings.findOneAndUpdate({ key: 'global' }, { $set: updates, $setOnInsert: { key: 'global' } }, { new: true, upsert: true });
    res.json({ success: true, settings });
  } catch (err) { next(err); }
});

// -----------------------------------------------------------------------------
// ERROR HANDLING — keep this after all routes
// -----------------------------------------------------------------------------
app.use((err, req, res, next) => {
  console.error('API error:', err);
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ success: false, message: err.code === 'LIMIT_FILE_SIZE' ? 'Receipt must be 2 MB or smaller.' : err.message });
  }
  if (err.message && err.message.includes('Receipt must be')) {
    return res.status(400).json({ success: false, message: err.message });
  }
  if (err.code === 11000) return res.status(409).json({ success: false, message: 'Email, phone or referral code already exists.' });
  res.status(err.statusCode || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' ? 'Server error. Check Render logs.' : (err.message || 'Server error.')
  });
});
app.use((req, res) => res.status(404).json({ success: false, message: `route not found: ${req.path}` }));

// -----------------------------------------------------------------------------
// START
// -----------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB connected');
    app.listen(PORT, '0.0.0.0', () => console.log(`Server listening on ${PORT}`));
  })
  .catch(err => {
    console.error('MongoDB connection failed:', err.message);
    process.exit(1);
  });
