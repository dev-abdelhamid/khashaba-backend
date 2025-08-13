import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import { body, validationResult } from 'express-validator';
import helmet from 'helmet';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { format, parse, isBefore, isAfter, startOfDay, addDays, subDays, subWeeks, subMonths, subYears } from 'date-fns';
import { ar } from 'date-fns/locale';
import { Server } from 'socket.io';
import http from 'http';
import rateLimit from 'express-rate-limit';
import nodemailer from 'nodemailer';
import winston from 'winston';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import { createObjectCsvWriter } from 'csv-writer';
import { createWriteStream } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import PDFDocument from 'pdfkit';

dotenv.config();

// التحقق من متغيرات البيئة
const requiredEnvVars = ['PORT', 'MONGODB_URI', 'CORS_ORIGIN', 'JWT_SECRET', 'EMAIL_USER', 'EMAIL_PASS', 'JWT_REFRESH_SECRET'];
requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    throw new Error(`المتغير المطلوب مفقود: ${varName}`);
  }
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      const allowedOrigins = [
        process.env.CORS_ORIGIN,
        'http://localhost:3000',
        'http://localhost:5173',
        'https://dr-khashaba.tsd-education.com',
        'https://dr-qami.vercel.app',
        'https://khashaba-dasbored.vercel.app',
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('غير مسموح به بواسطة CORS'));
      }
    },
    methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
    credentials: true,
  },
});

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// إعداد السجل (Logger)
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
    winston.format.errors({ stack: true })
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({ format: winston.format.simple() }),
  ],
});

// Middleware
app.use(compression());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com'],
      scriptSrc: ["'self'", 'https://cdn.tailwindcss.com'],
      connectSrc: [
        "'self'",
        process.env.CORS_ORIGIN,
        'http://localhost:3000',
        'http://localhost:5173',
        'https://dr-khashaba.tsd-education.com',
        'https://dr-qami.vercel.app',
        'https://khashaba-dasbored.vercel.app',
        `ws://localhost:${PORT}`,
        `wss://localhost:${PORT}`,
        `wss://khashaba-backend-production.up.railway.app`,
        `https://khashaba-backend-production.up.railway.app`,
      ],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'", 'https:'],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use(morgan('combined', { stream: { write: (message) => logger.info(message.trim()) } }));
app.use(cookieParser());
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      process.env.CORS_ORIGIN,
      'http://localhost:3000',
      'http://localhost:5173',
      'https://dr-khashaba.tsd-education.com',
      'https://dr-qami.vercel.app',
      'https://khashaba-dasbored.vercel.app',
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('غير مسموح به بواسطة CORS'));
    }
  },
  methods: ['GET', 'POST', 'PATCH', 'PUT', 'DELETE'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Set-Cookie'],
}));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقيقة
  max: 1000,
  message: { message: 'عدد كبير جدًا من الطلبات، حاول مجددًا لاحقًا' },
}));
app.use((req, res, next) => {
  logger.info(`طلب: ${req.method} ${req.url} البيانات: ${JSON.stringify(req.body)}`);
  next();
});
app.options('*', cors());

// Rate Limiting للحجوزات الجزئية
const partialRateLimiter = rateLimit({
  windowMs: 60 * 1000, // دقيقة واحدة
  max: 5,
  message: { message: 'عدد كبير جدًا من محاولات حفظ البيانات الجزئية، حاول مجددًا لاحقًا' },
});
app.use('/api/partial-bookings', partialRateLimiter);

// الاتصال بقاعدة البيانات MongoDB
mongoose.set('strictQuery', true);
mongoose.connect(MONGO_URI, {
  maxPoolSize: 10,
  minPoolSize: 2,
}).then(() => logger.info('تم الاتصال بـ MongoDB Atlas'))
  .catch((err) => {
    logger.error('خطأ في الاتصال بـ MongoDB:', err);
    process.exit(1);
  });

// تعريف النماذج (Schemas)
const patientSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  phone: { type: String, required: true, unique: true, trim: true },
  email: { type: String, trim: true, lowercase: true },
  isNewPatient: { type: Boolean, default: true },
  appointments: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' }],
}, { timestamps: true });

patientSchema.index({ phone: 1 }, { unique: true });
patientSchema.index({ createdAt: 1 });

const adminSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, lowercase: true },
  password: { type: String, required: true },
  refreshToken: { type: String },
}, { timestamps: true });

adminSchema.index({ username: 1 }, { unique: true });

const appointmentSchema = new mongoose.Schema({
  patient: { type: mongoose.Schema.Types.ObjectId, ref: 'Patient', required: true },
  date: { type: String, required: true },
  time: { type: String, required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'completed'], default: 'pending' },
  language: { type: String, enum: ['ar', 'en'], default: 'ar' },
  notes: { type: String, trim: true },
}, { timestamps: true });

appointmentSchema.index({ date: 1, time: 1 }, { unique: true });
appointmentSchema.index({ status: 1 });
appointmentSchema.index({ createdAt: 1 });

const activitySchema = new mongoose.Schema({
  appointmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Appointment' },
  action: { type: String, required: true },
  details: { type: String, required: true },
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
}, { timestamps: true });

activitySchema.index({ createdAt: -1 });

const partialBookingSchema = new mongoose.Schema({
  name: { type: String, trim: true },
  phone: { type: String, trim: true },
  email: { type: String, trim: true },
  date: { type: String },
  time: { type: String },
  notes: { type: String, trim: true },
  language: { type: String, enum: ['ar', 'en'] },
  isNewPatient: { type: Boolean },
}, { timestamps: true });

partialBookingSchema.index({ createdAt: -1 });

const visitSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  ip: String,
  userAgent: String,
}, { timestamps: true });

visitSchema.index({ timestamp: -1 });

const adClickSchema = new mongoose.Schema({
  timestamp: { type: Date, default: Date.now },
  campaign: { type: String, trim: true },
  ip: { type: String, trim: true },
}, { timestamps: true });

adClickSchema.index({ timestamp: -1 });

const Patient = mongoose.model('Patient', patientSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Appointment = mongoose.model('Appointment', appointmentSchema);
const Activity = mongoose.model('Activity', activitySchema);
const PartialBooking = mongoose.model('PartialBooking', partialBookingSchema);
const Visit = mongoose.model('Visit', visitSchema);
const AdClick = mongoose.model('AdClick', adClickSchema);

// إعداد البريد الإلكتروني
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100,
});

// دوال مساعدة
const sendEmailNotification = async (options) => {
  try {
    await transporter.sendMail(options);
    logger.info(`تم إرسال بريد إلكتروني إلى: ${options.to}`);
  } catch (error) {
    logger.error(`خطأ في إرسال البريد الإلكتروني إلى ${options.to}:`, error);
  }
};

const isValidAppointmentTime = (date, time) => {
  const appointmentDate = parse(date, 'yyyy-MM-dd', new Date());
  const now = startOfDay(new Date());
  const fourDaysFromNow = addDays(now, 4);

  if (isBefore(appointmentDate, now) || isAfter(appointmentDate, fourDaysFromNow)) return false;

  const hour = parseInt(time.split(':')[0], 10);
  return hour >= 9 && hour <= 21;
};

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.warn(`خطأ في التحقق: ${errors.array()[0].msg}`);
    return res.status(400).json({ message: errors.array()[0].msg });
  }
  next();
};

const verifyToken = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  if (!token) {
    logger.warn('لم يتم توفير توكن');
    return res.status(401).json({ message: 'لم يتم توفير توكن' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.adminId = decoded.adminId;
    logger.info(`تم التحقق من التوكن لـ adminId: ${req.adminId}`);
    next();
  } catch (error) {
    logger.error('خطأ في التحقق من JWT:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'انتهت صلاحية التوكن' });
    }
    return res.status(401).json({ message: 'توكن غير صالح' });
  }
};

const verifyRefreshToken = async (req, res, next) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    logger.warn('لم يتم توفير توكن التجديد');
    return res.status(401).json({ message: 'لم يتم توفير توكن التجديد' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const admin = await Admin.findById(decoded.adminId).lean();
    if (!admin || admin.refreshToken !== refreshToken) {
      return res.status(401).json({ message: 'توكن التجديد غير صالح' });
    }
    req.adminId = decoded.adminId;
    next();
  } catch (error) {
    logger.error('خطأ في التحقق من توكن التجديد:', error);
    return res.status(401).json({ message: 'توكن التجديد غير صالح أو منتهي الصلاحية' });
  }
};

// أحداث WebSocket
io.on('connection', (socket) => {
  logger.info(`تم اتصال العميل: ${socket.id}`);
  socket.on('disconnect', () => logger.info(`تم قطع اتصال العميل: ${socket.id}`));
});

// المسارات (Routes)
app.post('/api/admin/register', [
  body('username').trim().notEmpty().isLength({ min: 3 }).withMessage('اسم المستخدم يجب أن يكون 3 أحرف على الأقل'),
  body('password').trim().isLength({ min: 8 }).withMessage('كلمة المرور يجب أن تكون 8 أحرف على الأقل'),
  handleValidationErrors,
], async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingAdmin = await Admin.findOne({ username }).lean();
    if (existingAdmin) return res.status(400).json({ message: 'اسم المستخدم موجود بالفعل' });

    const hashedPassword = await bcrypt.hash(password, 12);
    const admin = new Admin({ username, password: hashedPassword });
    await admin.save();
    return res.status(201).json({ message: 'تم تسجيل المدير بنجاح' });
  } catch (error) {
    logger.error('خطأ في التسجيل:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.post('/api/admin/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 50 }), [
  body('username').trim().notEmpty().withMessage('اسم المستخدم مطلوب'),
  body('password').trim().notEmpty().withMessage('كلمة المرور مطلوبة'),
  handleValidationErrors,
], async (req, res) => {
  try {
    const { username, password } = req.body;
    const admin = await Admin.findOne({ username }).lean();
    if (!admin || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ message: 'بيانات الاعتماد غير صالحة' });
    }

    const token = jwt.sign({ adminId: admin._id }, JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ adminId: admin._id }, JWT_REFRESH_SECRET, { expiresIn: '7d' });
    await Admin.updateOne({ _id: admin._id }, { refreshToken });

    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 3600000, // 1 ساعة
      path: '/',
    });
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 7 * 24 * 3600000, // 7 أيام
      path: '/',
    });

    return res.json({ message: 'تم تسجيل الدخول بنجاح' });
  } catch (error) {
    logger.error('خطأ في تسجيل الدخول:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.post('/api/admin/refresh-token', verifyRefreshToken, async (req, res) => {
  try {
    const token = jwt.sign({ adminId: req.adminId }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      maxAge: 3600000, // 1 ساعة
      path: '/',
    });
    res.json({ message: 'تم تجديد التوكن' });
  } catch (error) {
    logger.error('خطأ في تجديد التوكن:', error);
    res.status(401).json({ message: 'توكن التجديد غير صالح أو منتهي الصلاحية' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
  });
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    path: '/',
  });
  res.json({ message: 'تم تسجيل الخروج بنجاح' });
});

app.get('/api/health', async (req, res) => {
  try {
    const [patientCount, appointmentCount] = await Promise.all([Patient.countDocuments(), Appointment.countDocuments()]);
    res.json({ status: 'OK', timestamp: new Date().toISOString(), patients: patientCount, appointments: appointmentCount });
  } catch (error) {
    logger.error('خطأ في فحص الحالة:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/dashboard/stats', verifyToken, async (req, res) => {
  try {
    const period = req.query.period || 'day';
    const now = new Date();
    let startDate;
    switch (period) {
      case 'day':
        startDate = subDays(now, 1);
        break;
      case 'week':
        startDate = subWeeks(now, 1);
        break;
      case 'month':
        startDate = subMonths(now, 1);
        break;
      case 'year':
        startDate = subYears(now, 1);
        break;
      default:
        startDate = subDays(now, 1);
    }

    const matchFilter = { createdAt: { $gte: startDate } };
    const today = format(new Date(), 'yyyy-MM-dd');

    const [
      totalPatients,
      totalAppointments,
      pendingAppointments,
      approvedAppointments,
      rejectedAppointments,
      completedAppointments,
      todaysAppointments,
      newPatients,
      returningPatients,
      languageBreakdown,
      visitsCount,
      partialsCount,
      adClicks,
    ] = await Promise.all([
      Patient.countDocuments(matchFilter),
      Appointment.countDocuments(matchFilter),
      Appointment.countDocuments({ ...matchFilter, status: 'pending' }),
      Appointment.countDocuments({ ...matchFilter, status: 'approved' }),
      Appointment.countDocuments({ ...matchFilter, status: 'rejected' }),
      Appointment.countDocuments({ ...matchFilter, status: 'completed' }),
      Appointment.find({ date: today }).populate('patient', 'name phone email').sort({ time: 1 }).lean(),
      Patient.countDocuments({ ...matchFilter, isNewPatient: true }),
      Patient.countDocuments({ ...matchFilter, isNewPatient: false }),
      Appointment.aggregate([{ $match: matchFilter }, { $group: { _id: '$language', count: { $sum: 1 } } }]),
      Visit.countDocuments(matchFilter),
      PartialBooking.countDocuments(matchFilter),
      AdClick.countDocuments(matchFilter),
    ]);

    res.json({
      totalPatients,
      totalAppointments,
      pendingAppointments,
      approvedAppointments,
      rejectedAppointments,
      completedAppointments,
      recentAppointments: todaysAppointments,
      newPatients,
      returningPatients,
      languageBreakdown,
      visitsCount,
      partialsCount,
      adClicks,
    });
  } catch (error) {
    logger.error('خطأ في الإحصائيات:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/appointments/export', verifyToken, async (req, res) => {
  try {
    const { status, date, format, language } = req.query;
    const query = {};
    if (status) query.status = status;
    if (date) query.date = date;

    const appointments = await Appointment.find(query).populate('patient', 'name phone email').sort({ date: 1, time: 1 }).lean();

    if (format === 'csv') {
      const csvWriter = createObjectCsvWriter({
        path: join(tmpdir(), `appointments_${Date.now()}.csv`),
        header: [
          { id: 'patientName', title: language === 'ar' ? 'الاسم' : 'Name' },
          { id: 'patientPhone', title: language === 'ar' ? 'الهاتف' : 'Phone' },
          { id: 'patientEmail', title: language === 'ar' ? 'الإيميل' : 'Email' },
          { id: 'date', title: language === 'ar' ? 'التاريخ' : 'Date' },
          { id: 'time', title: language === 'ar' ? 'الوقت' : 'Time' },
          { id: 'status', title: language === 'ar' ? 'الحالة' : 'Status' },
          { id: 'notes', title: language === 'ar' ? 'الملاحظات' : 'Notes' },
        ],
      });

      const records = appointments.map(apt => ({
        patientName: apt.patient.name,
        patientPhone: apt.patient.phone,
        patientEmail: apt.patient.email || '-',
        date: format(new Date(apt.date), 'dd/MM/yyyy', { locale: language === 'ar' ? ar : undefined }),
        time: apt.time,
        status: language === 'ar'
          ? { pending: 'معلق', approved: 'مؤكد', rejected: 'مرفوض', completed: 'مكتمل' }[apt.status]
          : apt.status.charAt(0).toUpperCase() + apt.status.slice(1),
        notes: apt.notes || '-',
      }));

      await csvWriter.writeRecords(records);
      res.download(join(tmpdir(), `appointments_${Date.now()}.csv`), `appointments_${date || 'all'}.csv`);
    } else if (format === 'pdf') {
      const doc = new PDFDocument({
        lang: language === 'ar' ? 'ar' : 'en',
        direction: language === 'ar' ? 'rtl' : 'ltr',
        size: 'A4',
        margin: 50,
      });
      const filePath = join(tmpdir(), `appointments_${Date.now()}.pdf`);
      const stream = createWriteStream(filePath);
      doc.pipe(stream);

      doc.font('Helvetica');
      doc.fontSize(20).text(language === 'ar' ? 'تقرير المواعيد' : 'Appointments Report', { align: 'center' });
      doc.moveDown(1);

      if (date) {
        doc.fontSize(12).text(
          `${language === 'ar' ? 'التاريخ' : 'Date'}: ${format(new Date(date), 'dd/MM/yyyy', { locale: language === 'ar' ? ar : undefined })}`,
          { align: 'center' }
        );
        doc.moveDown(0.5);
      }

      doc.fontSize(12).fillColor('black');
      const headers = language === 'ar'
        ? ['الاسم', 'الهاتف', 'الإيميل', 'التاريخ', 'الوقت', 'الحالة', 'الملاحظات']
        : ['Name', 'Phone', 'Email', 'Date', 'Time', 'Status', 'Notes'];
      const headerWidths = [100, 80, 100, 70, 50, 60, 100];
      let x = 50;
      headers.forEach((header, i) => {
        doc.text(header, x, doc.y, { width: headerWidths[i], align: language === 'ar' ? 'right' : 'left' });
        x += headerWidths[i];
      });
      doc.moveDown(0.5);

      doc.fontSize(10);
      appointments.forEach((apt, index) => {
        x = 50;
        const rowData = [
          apt.patient.name,
          apt.patient.phone,
          apt.patient.email || '-',
          format(new Date(apt.date), 'dd/MM/yyyy', { locale: language === 'ar' ? ar : undefined }),
          apt.time,
          language === 'ar'
            ? { pending: 'معلق', approved: 'مؤكد', rejected: 'مرفوض', completed: 'مكتمل' }[apt.status]
            : apt.status.charAt(0).toUpperCase() + apt.status.slice(1),
          apt.notes || '-',
        ];
        rowData.forEach((data, i) => {
          doc.text(data, x, doc.y, { width: headerWidths[i], align: language === 'ar' ? 'right' : 'left' });
          x += headerWidths[i];
        });
        doc.moveDown(0.5);
        if (index < appointments.length - 1) {
          doc.moveDown(0.5);
        }
      });

      doc.end();
      stream.on('finish', () => {
        res.download(filePath, `appointments_${date || 'all'}.pdf`);
      });
    } else {
      res.status(400).json({ message: 'صيغة غير صالحة' });
    }
  } catch (error) {
    logger.error('خطأ في التصدير:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/patients/incomplete', verifyToken, async (req, res) => {
  try {
    const patients = await Patient.find({ appointments: { $size: 0 } }).select('name phone email createdAt').lean();
    res.json(patients);
  } catch (error) {
    logger.error('خطأ في جلب المرضى غير المكتملين:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/activities', verifyToken, async (req, res) => {
  try {
    const activities = await Activity.find()
      .populate({
        path: 'appointmentId',
        populate: { path: 'patient', select: 'name phone email' },
      })
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();
    res.json(activities);
  } catch (error) {
    logger.error('خطأ في جلب الأنشطة:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/appointments/available/:date', async (req, res) => {
  try {
    const { date } = req.params;
    const parsedDate = parse(date, 'yyyy-MM-dd', new Date());
    if (isBefore(parsedDate, startOfDay(new Date()))) return res.status(400).json({ message: 'لا يمكن جلب الفترات الزمنية للتواريخ الماضية' });

    const bookedAppointments = await Appointment.find({ date }).select('time status').lean();

    const bookedMap = new Map(bookedAppointments.map(apt => [apt.time, apt.status === 'approved' ? 'confirmed' : apt.status]));

    const timeSlots = [];
    for (let hour = 9; hour <= 21; hour++) {
      for (let minute of ['00', '30']) {
        const time = `${hour.toString().padStart(2, '0')}:${minute}`;
        const status = bookedMap.get(time) || 'available';
        timeSlots.push({ time, status, available: status === 'available' });
      }
    }
    res.json(timeSlots);
  } catch (error) {
    logger.error('خطأ في جلب الفترات المتاحة:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.post('/api/patients/initial', [
  body('name').trim().notEmpty().isLength({ min: 3 }).withMessage('الاسم يجب أن يكون 3 أحرف على الأقل'),
  body('phone').trim().matches(/^\+?\d{10,15}$/).withMessage('رقم الهاتف غير صالح'),
  body('email').optional().isEmail().normalizeEmail().withMessage('البريد الإلكتروني غير صالح'),
  body('isNewPatient').optional().isBoolean().withMessage('علامة المريض الجديد غير صالحة'),
  handleValidationErrors,
], async (req, res) => {
  try {
    const { name, phone, email, isNewPatient } = req.body;
    let patient = await Patient.findOne({ phone }).lean();
    if (!patient) {
      patient = new Patient({ name, phone, email, isNewPatient: isNewPatient ?? true });
      await patient.save();
    } else {
      patient = await Patient.findOneAndUpdate(
        { phone },
        { name, email: email || patient.email, isNewPatient: isNewPatient ?? patient.isNewPatient, updatedAt: new Date() },
        { new: true }
      ).lean();
    }
    res.status(201).json({ message: 'تم حفظ بيانات المريض الأولية', patient });
  } catch (error) {
    logger.error('خطأ في بيانات المريض الأولية:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.post('/api/appointments', [
  body('name').trim().notEmpty().isLength({ min: 3 }).withMessage('الاسم يجب أن يكون 3 أحرف على الأقل'),
  body('phone').trim().matches(/^\+?\d{10,15}$/).withMessage('رقم الهاتف غير صالح'),
  body('email').optional().isEmail().normalizeEmail().withMessage('البريد الإلكتروني غير صالح'),
  body('date').trim().notEmpty().isISO8601().withMessage('صيغة التاريخ غير صالحة'),
  body('time').trim().notEmpty().matches(/^\d{2}:00$/).withMessage('صيغة الوقت غير صالحة'),
  body('language').optional().isIn(['ar', 'en']).withMessage('اللغة غير صالحة'),
  handleValidationErrors,
], async (req, res) => {
  try {
    const { name, phone, email, date, time, notes, language = 'ar' } = req.body;

    if (!isValidAppointmentTime(date, time)) return res.status(400).json({ message: language === 'ar' ? 'الموعد أو التاريخ غير صالح' : 'Invalid appointment time or date' });

    const existingAppointment = await Appointment.findOne({ date, time, status: 'approved' }).lean();
    if (existingAppointment) {
      return res.status(400).json({ message: language === 'ar' ? 'الموعد محجوز بالفعل' : 'Time slot already booked' });
    }

    let patient = await Patient.findOne({ phone }).lean();
    if (!patient) {
      patient = new Patient({ name, phone, email, isNewPatient: true });
      await patient.save();
    } else {
      patient = await Patient.findOneAndUpdate(
        { phone },
        { name, email: email || patient.email, updatedAt: new Date() },
        { new: true }
      ).lean();
    }

    const appointment = new Appointment({
      patient: patient._id,
      date,
      time,
      status: 'pending',
      language,
      notes,
    });
    await appointment.save();

    await Patient.updateOne({ _id: patient._id }, { $push: { appointments: appointment._id } });

    const populatedAppointment = await Appointment.findById(appointment._id).populate('patient', 'name phone email').lean();

    io.emit('newAppointment', populatedAppointment);

    sendEmailNotification({
      from: '"Khashaba Clinic" <no-reply@khashaba-clinics.com>',
      to: 'admin@khashaba-clinics.com',
      subject: language === 'ar' ? 'حجز موعد جديد' : 'New Appointment Booking',
      text: `حجز جديد:\nالاسم: ${name}\nالهاتف: ${phone}\nالبريد: ${email || 'غير متوفر'}\nالتاريخ: ${date}\nالوقت: ${time}\nالملاحظات: ${notes || 'لا يوجد'}`,
      html: `<h2>${language === 'ar' ? 'حجز موعد جديد' : 'New Appointment Booking'}</h2><p><strong>الاسم:</strong> ${name}</p><p><strong>الهاتف:</strong> ${phone}</p><p><strong>البريد:</strong> ${email || 'غير متوفر'}</p><p><strong>التاريخ:</strong> ${date}</p><p><strong>الوقت:</strong> ${time}</p><p><strong>الملاحظات:</strong> ${notes || 'لا يوجد'}</p>`,
    });

    res.status(201).json({ message: 'تم إنشاء الموعد بنجاح', appointment: populatedAppointment });
  } catch (error) {
    logger.error('خطأ في إنشاء الموعد:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.post('/api/visit', async (req, res) => {
  try {
    const visit = new Visit({
      ip: req.ip,
      userAgent: req.headers['user-agent'],
    });
    await visit.save();
    res.sendStatus(204);
  } catch (error) {
    logger.error('خطأ في تسجيل الزيارة:', error);
    res.sendStatus(500);
  }
});

app.post('/api/ad-clicks', async (req, res) => {
  try {
    const { campaign } = req.body;
    const adClick = new AdClick({
      campaign: campaign || 'default',
      ip: req.ip,
    });
    await adClick.save();
    res.status(201).json({ message: 'تم تسجيل النقر على الإعلان' });
  } catch (error) {
    logger.error('خطأ في تسجيل النقر على الإعلان:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.post('/api/partial-bookings', async (req, res) => {
  try {
    const partial = new PartialBooking(req.body);
    await partial.save();
    res.status(201).json({ message: 'تم حفظ البيانات الجزئية' });
  } catch (error) {
    logger.error('خطأ في الحجز الجزئي:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/partial-bookings', verifyToken, async (req, res) => {
  try {
    const partials = await PartialBooking.find().sort({ createdAt: -1 }).lean();
    const total = partials.length;
    const uniquePhones = [...new Set(partials.map(p => p.phone).filter(Boolean))].length;
    const languageBreakdown = await PartialBooking.aggregate([{ $group: { _id: '$language', count: { $sum: 1 } } }]);
    res.json({ partials, stats: { total, uniquePatients: uniquePhones, languageBreakdown } });
  } catch (error) {
    logger.error('خطأ في جلب الحجوزات الجزئية:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/appointments', verifyToken, async (req, res) => {
  try {
    const { status, date } = req.query;
    const query = {};
    if (status) query.status = status;
    if (date) query.date = date;

    const appointments = await Appointment.find(query).populate('patient', 'name phone email').sort({ date: 1, time: 1 }).lean();
    res.json(appointments);
  } catch (error) {
    logger.error('خطأ في جلب المواعيد:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.patch('/api/appointments/:id/status', verifyToken, [
  body('status').isIn(['pending', 'approved', 'rejected', 'completed']).withMessage('الحالة غير صالحة'),
  body('language').optional().isIn(['ar', 'en']).withMessage('اللغة غير صالحة'),
  handleValidationErrors,
], async (req, res) => {
  try {
    const { id } = req.params;
    const { status, language = 'ar' } = req.body;

    const appointment = await Appointment.findById(id);
    if (!appointment) return res.status(404).json({ message: language === 'ar' ? 'الموعد غير موجود' : 'Appointment not found' });

    if (status === 'approved') {
      const existingApproved = await Appointment.findOne({ date: appointment.date, time: appointment.time, status: 'approved' }).lean();
      if (existingApproved && existingApproved._id.toString() !== id) return res.status(400).json({ message: language === 'ar' ? 'الموعد محجوز مسبقًا' : 'Slot already approved for another appointment' });
    }

    appointment.status = status;
    appointment.updatedAt = new Date();
    await appointment.save();

    const activity = new Activity({ appointmentId: id, action: 'status_updated', details: `تم تغيير الحالة إلى ${status}`, adminId: req.adminId });
    await activity.save();

    const populatedAppointment = await Appointment.findById(id).populate('patient', 'name phone email').lean();

    io.emit('appointmentStatusUpdated', { appointmentId: id, status });

    if (populatedAppointment.patient.email) {
      sendEmailNotification({
        from: '"Khashaba Clinic" <no-reply@khashaba-clinics.com>',
        to: populatedAppointment.patient.email,
        subject: language === 'ar' ? 'تحديث حالة الموعد' : 'Appointment Status Update',
        text: `تم تحديث موعدك في ${appointment.date} الساعة ${appointment.time} إلى ${status}.`,
        html: `<h2>${language === 'ar' ? 'تحديث حالة الموعد' : 'Appointment Status Update'}</h2><p>تم تحديث موعدك في ${appointment.date} الساعة ${appointment.time} إلى ${status}.</p><p><strong>الاسم:</strong> ${populatedAppointment.patient.name}</p><p><strong>الهاتف:</strong> ${populatedAppointment.patient.phone}</p>`,
      });
    }

    res.json({ message: language === 'ar' ? 'تم تحديث حالة الموعد' : 'Appointment status updated', appointment: populatedAppointment });
  } catch (error) {
    logger.error('خطأ في تحديث الحالة:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.delete('/api/appointments/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const appointment = await Appointment.findById(id);
    if (!appointment) return res.status(404).json({ message: 'الموعد غير موجود' });

    await Appointment.findByIdAndDelete(id);
    await Patient.updateOne({ _id: appointment.patient }, { $pull: { appointments: id } });

    const activity = new Activity({
      appointmentId: id,
      action: 'deleted',
      details: `تم حذف الموعد لـ ${appointment.date} الساعة ${appointment.time}`,
      adminId: req.adminId,
    });
    await activity.save();

    io.emit('appointmentDeleted', { appointmentId: id });

    res.json({ message: 'تم حذف الموعد بنجاح' });
  } catch (error) {
    logger.error('خطأ في حذف الموعد:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/patients', verifyToken, async (req, res) => {
  try {
    const { search } = req.query;
    const query = search ? {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ]
    } : {};

    const patients = await Patient.find(query).populate('appointments').sort({ updatedAt: -1 }).lean();
    res.json(patients);
  } catch (error) {
    logger.error('خطأ في جلب المرضى:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/patients/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const patient = await Patient.findById(id).populate({
      path: 'appointments',
      options: { sort: { date: -1 } },
    }).lean();
    if (!patient) return res.status(404).json({ message: 'المريض غير موجود' });
    res.json(patient);
  } catch (error) {
    logger.error('خطأ في جلب المريض:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.put('/api/patients/:id', verifyToken, [
  body('name').trim().notEmpty().isLength({ min: 3 }).withMessage('الاسم يجب أن يكون 3 أحرف على الأقل'),
  body('phone').trim().matches(/^\+?\d{10,15}$/).withMessage('رقم الهاتف غير صالح'),
  body('email').optional().isEmail().normalizeEmail().withMessage('البريد الإلكتروني غير صالح'),
  body('isNewPatient').optional().isBoolean().withMessage('علامة المريض الجديد غير صالحة'),
  handleValidationErrors,
], async (req, res) => {
  try {
    const { id } = req.params;
    const { name, phone, email, isNewPatient } = req.body;

    const existingPatient = await Patient.findOne({ phone, _id: { $ne: id } }).lean();
    if (existingPatient) return res.status(400).json({ message: 'رقم الهاتف موجود بالفعل' });

    const patient = await Patient.findByIdAndUpdate(
      id,
      { name, phone, email, isNewPatient, updatedAt: new Date() },
      { new: true }
    ).lean();

    if (!patient) return res.status(404).json({ message: 'المريض غير موجود' });

    res.json({ message: 'تم تحديث المريض بنجاح', patient });
  } catch (error) {
    logger.error('خطأ في تحديث المريض:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.delete('/api/patients/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const patient = await Patient.findById(id);
    if (!patient) return res.status(404).json({ message: 'المريض غير موجود' });

    const appointments = await Appointment.find({ patient: id });
    if (appointments.length > 0) {
      return res.status(400).json({ message: 'لا يمكن حذف مريض لديه مواعيد موجودة' });
    }

    await Patient.findByIdAndDelete(id);
    res.json({ message: 'تم حذف المريض بنجاح' });
  } catch (error) {
    logger.error('خطأ في حذف المريض:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

app.get('/api/patients/:phone/appointments', async (req, res) => {
  try {
    const { phone } = req.params;
    const patient = await Patient.findOne({ phone }).lean();
    if (!patient) return res.status(404).json({ message: 'المريض غير موجود' });

    const appointments = await Appointment.find({ patient: patient._id })
      .populate('patient', 'name phone email')
      .sort({ date: -1, time: -1 })
      .lean();
    res.json(appointments);
  } catch (error) {
    logger.error('خطأ في جلب مواعيد المريض:', error);
    res.status(500).json({ message: 'خطأ في الخادم' });
  }
});

// معالجة الأخطاء
app.use((err, req, res, next) => {
  logger.error(`خطأ غير معالج: ${err.message}`, { stack: err.stack });
  res.status(500).json({ message: 'خطأ داخلي في الخادم' });
});

// تشغيل الخادم
server.listen(PORT, () => {
  logger.info(`الخادم يعمل على المنفذ ${PORT}`);
});

// الإغلاق الآمن
process.on('SIGTERM', async () => {
  logger.info('تلقي إشارة SIGTERM. إغلاق الخادم...');
  server.close(() => {
    logger.info('تم إغلاق الخادم.');
    mongoose.connection.close(false, () => {
      logger.info('تم إغلاق اتصال MongoDB.');
      process.exit(0);
    });
  });
});