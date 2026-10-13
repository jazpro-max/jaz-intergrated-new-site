/**
 * Wallet Platform - single-file backend
 * Covers: register, login, index, me, order, team, withdrawal, deposit,
 * settings, notification, support, forgot-password, change-pin,
 * transaction, change-password, admin.
 *
 * Env vars needed (set these in Render's dashboard, not in this file):
 * MONGO_URI, JWT_SECRET, PORT (optional), CLIENT_URL (optional)
 */

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
// ---------------------------------------------------------------------------
// MODELS
// ---------------------------------------------------------------------------

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    phone: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    pin: { type: String, select: false },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    status: { type: String, enum: ['active', 'suspended'], default: 'active' },
    referralCode: { type: String, unique: true },
    referredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    walletBalance: { type: Number, default: 0 },
    commissionBalance: { type: Number, default: 0 },
    resetPasswordToken: { type: String, select: false },
    resetPasswordExpire: { type: Date, select: false },
  },
  { timestamps: true }
);
userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});
userSchema.methods.matchPassword = function (entered) {
  return bcrypt.compare(entered, this.password);
};
userSchema.methods.setPin = async function (pin) {
  this.pin = await bcrypt.hash(pin, 10);
};
userSchema.methods.matchPin = function (entered) {
  return this.pin ? bcrypt.compare(entered, this.pin) : Promise.resolve(false);
};
const User = mongoose.model('User', userSchema);

const orderSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    planName: String,
    amount: { type: Number, required: true },
    dailyReturnPercent: { type: Number, default: 0 },
    durationDays: { type: Number, default: 30 },
    status: { type: String, enum: ['active', 'completed', 'cancelled'], default: 'active' },
  },
  { timestamps: true }
);
const Order = mongoose.model('Order', orderSchema);

const transactionSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdrawal', 'commission', 'order', 'adjustment'], required: true },
    amount: { type: Number, required: true },
    fee: { type: Number, default: 0 },
    status: { type: String, enum: ['pending', 'approved', 'rejected', 'completed'], default: 'pending' },
    method: String,
    accountDetails: String,
    note: String,
  },
  { timestamps: true }
);
const Transaction = mongoose.model('Transaction', transactionSchema);

const notificationSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    title: String,
    message: String,
    type: { type: String, default: 'info' },
    isRead: { type: Boolean, default: false },
    readBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  },
  { timestamps: true }
);
const Notification = mongoose.model('Notification', notificationSchema);

const supportSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    subject: String,
    message: String,
    status: { type: String, enum: ['open', 'pending', 'closed'], default: 'open' },
    replies: [
      {
        sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        senderRole: String,
        message: String,
        createdAt: { type: Date, default: Date.now },
      },
    ],
  },
  { timestamps: true }
);
const Support = mongoose.model('Support', supportSchema);

const settingsSchema = new mongoose.Schema({
  key: { type: String, default: 'global', unique: true },
  minDeposit: { type: Number, default: 1000 },
  minWithdrawal: { type: Number, default: 1000 },
  withdrawalFeePercent: { type: Number, default: 5 },
  referralLevel1Percent: { type: Number, default: 10 },
  referralLevel2Percent: { type: Number, default: 3 },
});
const Settings = mongoose.model('Settings', settingsSchema);
const getSettings = async () => (await Settings.findOne({ key: 'global' })) || Settings.create({ key: 'global' });

// ---------------------------------------------------------------------------
// AUTH MIDDLEWARE
// ---------------------------------------------------------------------------

const protect = async (req, res, next) => {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'No token' });
    }
    const decoded = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user) return res.status(401).json({ success: false, message: 'User not found' });
    if (user.status === 'suspended') return res.status(403).json({ success: false, message: 'Suspended' });
    req.user = user;
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
};
const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  next();
};
const genToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '7d' });
const genReferralCode = async (name) => {
  const base = (name || 'user').replace(/[^a-zA-Z]/g, '').slice(0, 4).toUpperCase() || 'USER';
  let code, exists = true;
  while (exists) {
    code = `${base}${Math.floor(1000 + Math.random() * 9000)}`;
    exists = await User.findOne({ referralCode: code });
  }
  return code;
};

// ---------------------------------------------------------------------------
// ROUTES: health
// ---------------------------------------------------------------------------
app.get('/api/health', (req, res) => res.json({ success: true, message: 'API is running' }));

// ---------------------------------------------------------------------------
// ROUTES: auth (register, login, forgot/reset/change password, change pin)
// ---------------------------------------------------------------------------

app.post('/api/register', async (req, res, next) => {
  try {
    const { name, email, phone, password, pin, referralCode } = req.body;
    if (!name || !email || !phone || !password) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }
    if (await User.findOne({ $or: [{ email }, { phone }] })) {
      return res.status(400).json({ success: false, message: 'Email or phone already registered' });
    }
    let referredBy = null;
    if (referralCode) {
      const referrer = await User.findOne({ referralCode });
      if (referrer) referredBy = referrer._id;
    }
    const user = new User({
      name, email, phone, password, referredBy,
      referralCode: await genReferralCode(name),
    });
  
    await user.save();
    res.status(201).json({
      success: true,
      token: genToken(user._id),
      user: { id: user._id, name: user.name, email: user.email, referralCode: user.referralCode, role: user.role },
    });
  } catch (err) { next(err); }
});

app.post('/api/login', async (req, res, next) => {
  try {
    const { emailOrPhone, password } = req.body;
    const user = await User.findOne({ $or: [{ email: emailOrPhone?.toLowerCase() }, { phone: emailOrPhone }] }).select('+password');
    if (!user || !(await user.matchPassword(password))) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    if (user.status === 'suspended') return res.status(403).json({ success: false, message: 'Account suspended' });
    res.json({ success: true, token: genToken(user._id), user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) { next(err); }
});

app.post('/api/auth/forgot-password', async (req, res, next) => {
  try {
    const user = await User.findOne({ email: (req.body.email || '').toLowerCase() });
    if (!user) return res.json({ success: true, message: 'If that email exists, a reset link has been sent' });
    const rawToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = crypto.createHash('sha256').update(rawToken).digest('hex');
    user.resetPasswordExpire = Date.now() + 30 * 60 * 1000;
    await user.save();
    // NOTE: plug in real email sending here (e.g. nodemailer). For now the
    // raw token is returned in the response so you can test end-to-end.
    res.json({ success: true, message: 'Reset token generated', resetToken: rawToken });
  } catch (err) { next(err); }
});

app.put('/api/auth/reset-password/:token', async (req, res, next) => {
  try {
    const hashed = crypto.createHash('sha256').update(req.params.token).digest('hex');
    const user = await User.findOne({ resetPasswordToken: hashed, resetPasswordExpire: { $gt: Date.now() } }).select('+resetPasswordToken +resetPasswordExpire');
    if (!user) return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();
    res.json({ success: true, message: 'Password reset. Please log in.' });
  } catch (err) { next(err); }
});

app.put('/api/auth/change-password', protect, async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('+password');
    if (!(await user.matchPassword(req.body.currentPassword))) {
      return res.status(401).json({ success: false, message: 'Current password incorrect' });
    }
    user.password = req.body.newPassword;
    await user.save();
    res.json({ success: true, message: 'Password changed' });
  } catch (err) { next(err); }
});

app.put('/api/auth/change-pin', protect, async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id).select('+pin');
    if (user.pin && !(await user.matchPin(req.body.currentPin))) {
      return res.status(401).json({ success: false, message: 'Current PIN incorrect' });
    }
    if (!/^\d{4,6}$/.test(req.body.newPin)) {
      return res.status(400).json({ success: false, message: 'PIN must be 4-6 digits' });
    }
    await user.setPin(req.body.newPin);
    await user.save();
    res.json({ success: true, message: 'PIN changed' });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------------------------
// ROUTES: me / index (dashboard) / settings (profile)
// ---------------------------------------------------------------------------

app.get('/api/users/me', protect, (req, res) => res.json({ success: true, user: req.user }));

app.put('/api/users/me', protect, async (req, res, next) => {
  try {
    const updates = {};
    ['name', 'phone', 'avatar'].forEach((f) => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });
    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true });
    res.json({ success: true, user });
  } catch (err) { next(err); }
});

app.get('/api/users/dashboard', protect, async (req, res, next) => {
  try {
    const activeOrders = await Order.countDocuments({ user: req.user._id, status: 'active' });
    const referralCount = await User.countDocuments({ referredBy: req.user._id });
    res.json({
      success: true,
      dashboard: {
        walletBalance: req.user.walletBalance,
        commissionBalance: req.user.commissionBalance,
        activeOrders,
        referralCount,
      },
    });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------------------------
// ROUTES: team
// ---------------------------------------------------------------------------

app.get('/api/team', protect, async (req, res, next) => {
  try {
    const level1 = await User.find({ referredBy: req.user._id }).select('name email phone createdAt');
    res.json({ success: true, team: { referralCode: req.user.referralCode, level1Count: level1.length, level1 } });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------------------------
// ROUTES: wallet (deposit, withdrawal)
// ---------------------------------------------------------------------------

app.post('/api/wallet/deposit', protect, async (req, res, next) => {
  try {
    const settings = await getSettings();
    const { amount, method, note } = req.body;
    if (!amount || amount < settings.minDeposit) {
      return res.status(400).json({ success: false, message: `Minimum deposit is ${settings.minDeposit}` });
    }
    const tx = await Transaction.create({ user: req.user._id, type: 'deposit', amount, method, note });
    res.status(201).json({ success: true, transaction: tx });
  } catch (err) { next(err); }
});

app.get('/api/wallet/deposits', protect, async (req, res, next) => {
  try {
    res.json({ success: true, deposits: await Transaction.find({ user: req.user._id, type: 'deposit' }).sort('-createdAt') });
  } catch (err) { next(err); }
});

app.post('/api/wallet/withdraw', protect, async (req, res, next) => {
  try {
    const settings = await getSettings();
    const { amount, method, accountDetails, pin } = req.body;
    if (!amount || amount < settings.minWithdrawal) {
      return res.status(400).json({ success: false, message: `Minimum withdrawal is ${settings.minWithdrawal}` });
    }
    const user = await User.findById(req.user._id).select('+pin');
    if (!(await user.matchPin(pin))) return res.status(401).json({ success: false, message: 'Incorrect PIN' });
    const fee = (amount * settings.withdrawalFeePercent) / 100;
    if (user.walletBalance < amount + fee) return res.status(400).json({ success: false, message: 'Insufficient balance' });
    user.walletBalance -= amount + fee;
    await user.save();
    const tx = await Transaction.create({ user: user._id, type: 'withdrawal', amount, fee, method, accountDetails });
    res.status(201).json({ success: true, transaction: tx, walletBalance: user.walletBalance });
  } catch (err) { next(err); }
});

app.get('/api/wallet/withdrawals', protect, async (req, res, next) => {
  try {
    res.json({ success: true, withdrawals: await Transaction.find({ user: req.user._id, type: 'withdrawal' }).sort('-createdAt') });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------------------------
// ROUTES: order
// ---------------------------------------------------------------------------

app.post('/api/orders', protect, async (req, res, next) => {
  try {
    const { planName, amount, dailyReturnPercent, durationDays, pin } = req.body;
    const user = await User.findById(req.user._id).select('+pin');
    if (!(await user.matchPin(pin))) return res.status(401).json({ success: false, message: 'Incorrect PIN' });
    if (user.walletBalance < amount) return res.status(400).json({ success: false, message: 'Insufficient balance' });
    user.walletBalance -= amount;
    await user.save();
    const order = await Order.create({ user: user._id, planName, amount, dailyReturnPercent, durationDays });
    await Transaction.create({ user: user._id, type: 'order', amount, status: 'completed', note: `Investment in ${planName}` });
    res.status(201).json({ success: true, order, walletBalance: user.walletBalance });
  } catch (err) { next(err); }
});

app.get('/api/orders', protect, async (req, res, next) => {
  try {
    res.json({ success: true, orders: await Order.find({ user: req.user._id }).sort('-createdAt') });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------------------------
// ROUTES: transaction (history)
// ---------------------------------------------------------------------------

app.get('/api/transactions', protect, async (req, res, next) => {
  try {
    const filter = { user: req.user._id };
    if (req.query.type) filter.type = req.query.type;
    res.json({ success: true, transactions: await Transaction.find(filter).sort('-createdAt') });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------------------------
// ROUTES: notification
// ---------------------------------------------------------------------------

app.get('/api/notifications', protect, async (req, res, next) => {
  try {
    const notes = await Notification.find({ $or: [{ user: req.user._id }, { user: null }] }).sort('-createdAt');
    res.json({ success: true, notifications: notes });
  } catch (err) { next(err); }
});

app.put('/api/notifications/:id/read', protect, async (req, res, next) => {
  try {
    const note = await Notification.findById(req.params.id);
    if (!note) return res.status(404).json({ success: false, message: 'Not found' });
    if (note.user) note.isRead = true;
    else if (!note.readBy.some((id) => id.equals(req.user._id))) note.readBy.push(req.user._id);
    await note.save();
    res.json({ success: true });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------------------------
// ROUTES: support
// ---------------------------------------------------------------------------

app.post('/api/support', protect, async (req, res, next) => {
  try {
    const ticket = await Support.create({ user: req.user._id, subject: req.body.subject, message: req.body.message });
    res.status(201).json({ success: true, ticket });
  } catch (err) { next(err); }
});

app.get('/api/support', protect, async (req, res, next) => {
  try {
    res.json({ success: true, tickets: await Support.find({ user: req.user._id }).sort('-createdAt') });
  } catch (err) { next(err); }
});

app.post('/api/support/:id/reply', protect, async (req, res, next) => {
  try {
    const ticket = await Support.findById(req.params.id);
    if (!ticket) return res.status(404).json({ success: false, message: 'Not found' });
    if (!ticket.user.equals(req.user._id) && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Not authorized' });
    }
    ticket.replies.push({ sender: req.user._id, senderRole: req.user.role, message: req.body.message });
    await ticket.save();
    res.json({ success: true, ticket });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------------------------
// ROUTES: admin
// ---------------------------------------------------------------------------

app.get('/api/admin/dashboard', protect, adminOnly, async (req, res, next) => {
  try {
    const [totalUsers, pendingDeposits, pendingWithdrawals] = await Promise.all([
      User.countDocuments(),
      Transaction.countDocuments({ type: 'deposit', status: 'pending' }),
      Transaction.countDocuments({ type: 'withdrawal', status: 'pending' }),
    ]);
    res.json({ success: true, stats: { totalUsers, pendingDeposits, pendingWithdrawals } });
  } catch (err) { next(err); }
});

app.get('/api/admin/users', protect, adminOnly, async (req, res, next) => {
  try {
    res.json({ success: true, users: await User.find().sort('-createdAt') });
  } catch (err) { next(err); }
});

app.put('/api/admin/users/:id/status', protect, adminOnly, async (req, res, next) => {
  try {
    const user = await User.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
    res.json({ success: true, user });
  } catch (err) { next(err); }
});

app.get('/api/admin/deposits', protect, adminOnly, async (req, res, next) => {
  try {
    const filter = { type: 'deposit' };
    if (req.query.status) filter.status = req.query.status;
    res.json({ success: true, deposits: await Transaction.find(filter).populate('user', 'name email').sort('-createdAt') });
  } catch (err) { next(err); }
});

app.put('/api/admin/deposits/:id', protect, adminOnly, async (req, res, next) => {
  try {
    const tx = await Transaction.findById(req.params.id);
    if (!tx || tx.status !== 'pending') return res.status(400).json({ success: false, message: 'Not pending' });
    if (req.body.action === 'approve') {
      const user = await User.findById(tx.user);
      user.walletBalance += tx.amount;
      await user.save();
      tx.status = 'approved';

      // pay level-1 referral commission
      const settings = await getSettings();
      if (user.referredBy) {
        const referrer = await User.findById(user.referredBy);
        if (referrer) {
          const commission = (tx.amount * settings.referralLevel1Percent) / 100;
          referrer.walletBalance += commission;
          referrer.commissionBalance += commission;
          await referrer.save();
          await Transaction.create({ user: referrer._id, type: 'commission', amount: commission, status: 'completed', note: `Referral commission from ${user.name}` });
        }
      }
    } else {
      tx.status = 'rejected';
    }
    await tx.save();
    res.json({ success: true, transaction: tx });
  } catch (err) { next(err); }
});

app.get('/api/admin/withdrawals', protect, adminOnly, async (req, res, next) => {
  try {
    const filter = { type: 'withdrawal' };
    if (req.query.status) filter.status = req.query.status;
    res.json({ success: true, withdrawals: await Transaction.find(filter).populate('user', 'name email').sort('-createdAt') });
  } catch (err) { next(err); }
});

app.put('/api/admin/withdrawals/:id', protect, adminOnly, async (req, res, next) => {
  try {
    const tx = await Transaction.findById(req.params.id);
    if (!tx || tx.status !== 'pending') return res.status(400).json({ success: false, message: 'Not pending' });
    if (req.body.action === 'approve') {
      tx.status = 'approved';
    } else {
      const user = await User.findById(tx.user);
      user.walletBalance += tx.amount + tx.fee;
      await user.save();
      tx.status = 'rejected';
    }
    await tx.save();
    res.json({ success: true, transaction: tx });
  } catch (err) { next(err); }
});

app.get('/api/admin/settings', protect, adminOnly, async (req, res, next) => {
  try {
    res.json({ success: true, settings: await getSettings() });
  } catch (err) { next(err); }
});

app.put('/api/admin/settings', protect, adminOnly, async (req, res, next) => {
  try {
    const settings = await getSettings();
    Object.assign(settings, req.body);
    await settings.save();
    res.json({ success: true, settings });
  } catch (err) { next(err); }
});

app.post('/api/admin/notifications', protect, adminOnly, async (req, res, next) => {
  try {
    const note = await Notification.create({ user: req.body.userId || null, title: req.body.title, message: req.body.message, type: req.body.type || 'info' });
    res.status(201).json({ success: true, notification: note });
  } catch (err) { next(err); }
});


// ---- Extra admin routes for professional admin panel ----
app.post('/api/admin/update-balance', protect, adminOnly, async (req, res, next) => {
  try {
    const { phone, type, action, amount, note } = req.body;
    if (!phone || !type || amount === undefined) {
      return res.status(400).json({ success: false, message: 'phone, type and amount are required' });
    }
    const field = type === 'commission' ? 'commissionBalance' : 'walletBalance';
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    const num = parseFloat(amount);
    if (isNaN(num) || num < 0) return res.status(400).json({ success: false, message: 'Invalid amount' });

    const oldValue = user[field] || 0;
    let newValue = oldValue;
    if (action === 'add') newValue = oldValue + num;
    else if (action === 'subtract') newValue = Math.max(0, oldValue - num);
    else newValue = num; // set

    user[field] = newValue;
    await user.save();

    res.json({
      success: true,
      message: `${field} updated`,
      data: { phone, field, oldValue, newValue, note: note || '' }
    });
  } catch (err) { next(err); }
});

app.post('/api/admin/update-status', protect, adminOnly, async (req, res, next) => {
  try {
    const { phone, status } = req.body;
    if (!phone || !['active', 'suspended'].includes(status)) {
      return res.status(400).json({ success: false, message: 'phone and valid status required' });
    }
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    if (user.role === 'admin') return res.status(403).json({ success: false, message: 'Cannot change admin status' });
    user.status = status;
    await user.save();
    res.json({ success: true, message: `Account ${status}`, user });
  } catch (err) { next(err); }
});

app.get('/api/admin/orders', protect, adminOnly, async (req, res, next) => {
  try {
    const orders = await Order.find().populate('user', 'name phone email').sort('-createdAt').limit(200);
    res.json({ success: true, orders });
  } catch (err) { next(err); }
});

app.get('/api/admin/transactions', protect, adminOnly, async (req, res, next) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.type) filter.type = req.query.type;
    const transactions = await Transaction.find(filter)
      .populate('user', 'name phone email')
      .sort('-createdAt')
      .limit(300);
    res.json({ success: true, transactions });
  } catch (err) { next(err); }
});

app.post('/api/admin/transaction/approve', protect, adminOnly, async (req, res, next) => {
  try {
    const tx = await Transaction.findById(req.body.id);
    if (!tx || tx.status !== 'pending') {
      return res.status(400).json({ success: false, message: 'Transaction not pending' });
    }
    const user = await User.findById(tx.user);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    if (tx.type === 'deposit') {
      user.walletBalance += tx.amount;
      await user.save();
      // referral commission
      const settings = await getSettings();
      if (user.referredBy) {
        const referrer = await User.findById(user.referredBy);
        if (referrer) {
          const commission = (tx.amount * (settings.referralLevel1Percent || 10)) / 100;
          referrer.walletBalance += commission;
          referrer.commissionBalance += commission;
          await referrer.save();
        }
      }
    } else if (tx.type === 'withdrawal') {
      if (user.walletBalance < tx.amount) {
        return res.status(400).json({ success: false, message: 'Insufficient balance' });
      }
      user.walletBalance -= tx.amount;
      await user.save();
    }
    tx.status = 'approved';
    await tx.save();
    res.json({ success: true, message: 'Transaction approved' });
  } catch (err) { next(err); }
});

app.post('/api/admin/transaction/reject', protect, adminOnly, async (req, res, next) => {
  try {
    const tx = await Transaction.findById(req.body.id);
    if (!tx || tx.status !== 'pending') {
      return res.status(400).json({ success: false, message: 'Transaction not pending' });
    }
    tx.status = 'rejected';
    if (req.body.note) tx.note = req.body.note;
    await tx.save();
    res.json({ success: true, message: 'Transaction rejected' });
  } catch (err) { next(err); }
});

app.post('/api/admin/reset-user', protect, adminOnly, async (req, res, next) => {
  try {
    const { phone } = req.body;
    const user = await User.findOne({ phone });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    user.walletBalance = 0;
    user.commissionBalance = 0;
    await user.save();
    res.json({ success: true, message: 'User balances reset to 0' });
  } catch (err) { next(err); }
});


// One-time helper: promote a user to admin by referral code (call once, then
// remove or protect this route). Convenient when you have no local shell.
app.post('/api/admin/bootstrap', async (req, res, next) => {
  try {
    const { email, secret } = req.body;
    if (secret !== process.env.JWT_SECRET) return res.status(403).json({ success: false, message: 'Not authorized' });
    const user = await User.findOneAndUpdate({ email }, { role: 'admin' }, { new: true });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    res.json({ success: true, message: `${email} is now an admin` });
  } catch (err) { next(err); }
});

// ---------------------------------------------------------------------------
// ERROR HANDLING + STARTUP
// ---------------------------------------------------------------------------

app.use((req, res) => res.status(404).json({ success: false, message: `Route not found: ${req.originalUrl}` }));

app.use((err, req, res, next) => {
  console.error(err);
  let status = 500, message = err.message || 'Server error';
  if (err.code === 11000) { status = 400; message = 'Duplicate value - email or phone already in use'; }
  if (err.name === 'ValidationError') { status = 400; message = Object.values(err.errors).map((e) => e.message).join(', '); }
  res.status(status).json({ success: false, message });
});

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB connected');
    const PORT = process.env.PORT || 5000;
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  });
