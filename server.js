const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const sanitize = require('sanitize-html');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

app.use(compression());
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://js.stripe.com"],
        frameSrc: ["'self'", "https://js.stripe.com"],
        connectSrc: ["'self'", "https://api.stripe.com"],
      },
    },
  })
);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  }
  next();
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
});
app.use(limiter);

app.use('/assets', express.static(path.join(__dirname, 'public/assets'), { maxAge: '7d', etag: true, lastModified: true }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', etag: true, lastModified: true }));

const bookingsStore = {};
const ordersStore = {};
const blockedDatesStore = [];
const reviewsStore = [];
const servicesStore = {
  StandardRoom: { price: '2000 ₽/ночь', name: { ru: 'Стандартная комната', en: 'Standard Room' }, description: { ru: 'Уютная комната для отдыха', en: 'Cozy room for a relaxing stay' } },
  LuxRoom: { price: '3500 ₽/ночь', name: { ru: 'Люкс', en: 'Lux Room' }, description: { ru: 'Роскошная комната с премиум-удобствами', en: 'Luxurious room with premium amenities' } },
  Sauna: { price: '1500 ₽/час', name: { ru: 'Сауна', en: 'Sauna' }, description: { ru: 'Теплая и расслабляющая сауна', en: 'Warm and relaxing sauna experience' } },
  Banya: { price: '2000 ₽/час', name: { ru: 'Баня', en: 'Banya' }, description: { ru: 'Традиционная русская баня с паром', en: 'Traditional Russian banya with steam' } },
  Kitchen: { price: '1000 ₽/час', name: { ru: 'Кухня', en: 'Kitchen' }, description: { ru: 'Небольшая кухня для ваших кулинарных нужд', en: 'Small kitchen for your culinary needs' } },
  Banquet: { price: '5000 ₽/час + 500 ₽/гость', name: { ru: 'Банкет', en: 'Banquet' }, description: { ru: 'Идеально для свадеб и торжеств', en: 'Perfect for weddings and celebrations' } },
};

const ADMIN_PHONE = '+79991234567';
const ADMIN_PASSWORD = 'Admin$ecret2025';
const JWT_SECRET = 'secret_key_very_secure_2025';
const otps = {};

const normalizePhone = (phone) => {
  let normalized = phone.replace(/\D/g, '');
  if (normalized.startsWith('8') && normalized.length === 11) return '+7' + normalized.slice(1);
  if (normalized.length === 10) return '+7' + normalized;
  if (normalized.startsWith('7') && normalized.length === 11) return '+' + normalized;
  return phone;
};

const refreshData = () => {
  setInterval(() => console.log('Server: Refreshing in-memory data...'), 300000);
};
refreshData();

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

app.post('/api/register', (req, res) => {
  const { phone } = req.body;
  const normalizedPhone = normalizePhone(phone);
  if (!normalizedPhone.match(/^\+7\d{10}$/)) return res.status(400).json({ error: 'Invalid phone format' });
  const token = jwt.sign({ phone: normalizedPhone }, JWT_SECRET, { expiresIn: '1h' });
  if (!bookingsStore[normalizedPhone]) bookingsStore[normalizedPhone] = [];
  if (!ordersStore[normalizedPhone]) ordersStore[normalizedPhone] = [];
  res.status(201).json({ token });
});

app.post('/api/login', (req, res) => {
  const { phoneOrEmail, password } = req.body;
  const normalizedPhone = normalizePhone(phoneOrEmail);
  if (!normalizedPhone.match(/^\+7\d{10}$/)) return res.status(400).json({ error: 'Invalid phone format' });

  if (normalizedPhone === ADMIN_PHONE) {
    if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Invalid admin password' });
    const token = jwt.sign({ phone: normalizedPhone }, JWT_SECRET, { expiresIn: '1h' });
    if (!bookingsStore[normalizedPhone]) bookingsStore[normalizedPhone] = [];
    if (!ordersStore[normalizedPhone]) ordersStore[normalizedPhone] = [];
    return res.status(200).json({ token });
  }

  const otp = Math.floor(1000 + Math.random() * 9000).toString();
  otps[normalizedPhone] = otp;
  console.log(`OTP for ${normalizedPhone}: ${otp}`);
  const token = jwt.sign({ phone: normalizedPhone }, JWT_SECRET, { expiresIn: '1h' });
  if (!bookingsStore[normalizedPhone]) bookingsStore[normalizedPhone] = [];
  if (!ordersStore[normalizedPhone]) ordersStore[normalizedPhone] = [];
  res.status(200).json({ token, message: 'OTP sent to server console' });
});

app.post('/api/verify-otp', (req, res) => {
  const { phone, otp } = req.body;
  const normalizedPhone = normalizePhone(phone);
  if (!normalizedPhone.match(/^\+7\d{10}$/)) return res.status(400).json({ error: 'Invalid phone format' });
  if (otps[normalizedPhone] && otps[normalizedPhone] === otp) {
    delete otps[normalizedPhone];
    res.status(200).json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid OTP' });
  }
});

app.get('/api/reviews', authenticateToken, (req, res) => res.status(200).json(reviewsStore));

app.post('/api/reviews', authenticateToken, (req, res) => {
  const { name, email, review } = req.body;
  if (!name || !email || !review) return res.status(400).json({ error: 'Missing required fields' });
  const newReview = {
    id: reviewsStore.length + 1,
    name: sanitize(name),
    email: sanitize(email),
    review: sanitize(review),
    user: req.user.phone,
  };
  reviewsStore.push(newReview);
  res.status(201).json(newReview);
});

app.post('/api/contact', authenticateToken, (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) return res.status(400).json({ error: 'Missing required fields' });
  console.log('Contact form submitted:', { name, email, message });
  res.status(200).json({ message: 'Contact form received' });
});

app.get('/api/blocked-dates', authenticateToken, (req, res) => res.status(200).json(blockedDatesStore));

app.post('/api/blocked-dates', authenticateToken, (req, res) => {
  if (req.user.phone !== ADMIN_PHONE) return res.status(403).json({ error: 'Forbidden' });
  const { service, date } = req.body;
  if (!service || !date) return res.status(400).json({ error: 'Missing required fields' });
  if (blockedDatesStore.some((b) => b.service === service && b.date === date)) return res.status(409).json({ error: 'Date already blocked' });
  blockedDatesStore.push({ service, date });
  res.status(201).json({ service, date });
});

app.delete('/api/blocked-dates/:index', authenticateToken, (req, res) => {
  if (req.user.phone !== ADMIN_PHONE) return res.status(403).json({ error: 'Forbidden' });
  const index = parseInt(req.params.index);
  if (isNaN(index) || index < 0 || index >= blockedDatesStore.length) return res.status(404).json({ error: 'Blocked date not found' });
  blockedDatesStore.splice(index, 1);
  res.status(204).send();
});

app.get('/api/bookings', authenticateToken, (req, res) => {
  if (req.user.phone === ADMIN_PHONE) return res.status(200).json(Object.values(bookingsStore).flat());
  res.status(200).json(bookingsStore[req.user.phone] || []);
});

app.post('/api/bookings/check', authenticateToken, (req, res) => {
  const { service, date, endDate, duration } = req.body;
  const isHourly = ['Sauna', 'Banya', 'Banquet', 'Kitchen'].includes(service);
  if (isHourly) {
    const [dateStr, hour] = date.split(' ');
    const startHour = parseInt(hour, 10);
    for (let i = 0; i < duration; i++) {
      const checkHour = String((startHour + i) % 24).padStart(2, '0');
      if (blockedDatesStore.some((b) => b.service === service && b.date === `${dateStr} ${checkHour}:00`)) {
        return res.status(409).json({ error: 'Time blocked' });
      }
    }
  } else if (endDate) {
    const start = new Date(date);
    const end = new Date(endDate);
    start.setHours(0, 0, 0, 0);
    end.setHours(0, 0, 0, 0);
    for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
      const checkDate = d.toISOString().split('T')[0];
      if (blockedDatesStore.some((b) => b.service === service && b.date === checkDate)) {
        return res.status(409).json({ error: 'Date blocked' });
      }
    }
  } else {
    if (blockedDatesStore.some((b) => b.service === service && b.date === date)) return res.status(409).json({ error: 'Date blocked' });
  }
  res.status(200).json({ message: 'Available' });
});

app.post('/api/bookings', authenticateToken, (req, res) => {
  const { service, cost, date, endDate, duration, paymentTime, isConfirmed, guestCount, checkInTime, comment, banquetExtras, kitchenMenu } = req.body;
  if (!service || !cost || !date) return res.status(400).json({ error: 'Missing required fields' });

  console.log('Server: Received booking data:', req.body);

  let totalCost = cost;

  if (!cost || cost === '') {
    const basePrice = parseFloat(servicesStore[service].price.split(' ')[0]);
    if (service === 'Banquet' && guestCount) {
      const guestCost = 500 * guestCount;
      const hourlyCost = basePrice * (duration || 1);
      const extrasCost = banquetExtras ? banquetExtras.reduce((sum, extra) => sum + (extra === 'Decoration' ? 2000 : extra === 'Music' ? 3000 : extra === 'Photographer' ? 4000 : 0), 0) : 0;
      totalCost = `${hourlyCost + guestCost + extrasCost} ₽`;
    } else if (service === 'Kitchen' && kitchenMenu) {
      const hourlyCost = basePrice * (duration || 1);
      const menuCost = kitchenMenu.reduce((sum, item) => sum + (item === 'CheesePlatter' ? 500 : item === 'Bruschetta' ? 300 : item === 'GrilledChicken' ? 800 : item === 'PastaCarbonara' ? 600 : item === 'Lemonade' ? 200 : item === 'Coffee' ? 150 : 0), 0);
      totalCost = `${hourlyCost + menuCost} ₽`;
    } else if (['StandardRoom', 'LuxRoom'].includes(service) && endDate) {
      const days = Math.ceil((new Date(endDate) - new Date(date)) / (1000 * 60 * 60 * 24));
      totalCost = `${basePrice * days} ₽`;
    } else if (['Sauna', 'Banya'].includes(service)) {
      totalCost = `${basePrice * (duration || 1)} ₽`;
    }
  }

  const sanitizedBooking = {
    user: req.user.phone,
    service: sanitize(service),
    cost: totalCost,
    date: sanitize(date),
    endDate: endDate ? sanitize(endDate) : null,
    duration: parseInt(duration, 10) || 1,
    paymentTime: paymentTime || new Date().toISOString(),
    isConfirmed: isConfirmed || false,
    isPaid: false,
    ...(guestCount && { guestCount: parseInt(guestCount, 10) }),
    ...(checkInTime && { checkInTime: sanitize(checkInTime) }),
    ...(comment && { comment: sanitize(comment) }),
    ...(banquetExtras && { banquetExtras }),
    ...(kitchenMenu && { kitchenMenu }),
  };

  if (!bookingsStore[req.user.phone]) bookingsStore[req.user.phone] = [];
  bookingsStore[req.user.phone].push(sanitizedBooking);

  console.log('Server: Saved booking:', sanitizedBooking);

  res.status(201).json(sanitizedBooking);
});

app.post('/api/bookings/:index/pay', authenticateToken, (req, res) => {
  const index = parseInt(req.params.index);
  if (!bookingsStore[req.user.phone] || index < 0 || index >= bookingsStore[req.user.phone].length) {
    return res.status(404).json({ error: 'Booking not found' });
  }
  bookingsStore[req.user.phone][index].isPaid = true;
  res.status(200).json(bookingsStore[req.user.phone][index]);
});

app.put('/api/bookings/:index', authenticateToken, (req, res) => {
  if (req.user.phone !== ADMIN_PHONE) return res.status(403).json({ error: 'Forbidden' });
  const index = parseInt(req.params.index);
  const allBookings = Object.values(bookingsStore).flat();
  if (isNaN(index) || index < 0 || index >= allBookings.length) return res.status(404).json({ error: 'Booking not found' });

  const existingBooking = allBookings[index];
  const updatedBooking = {
    ...existingBooking,
    ...req.body,
    checkInTime: req.body.checkInTime ? sanitize(req.body.checkInTime) : existingBooking.checkInTime,
    comment: req.body.comment ? sanitize(req.body.comment) : existingBooking.comment,
    isConfirmed: req.body.isConfirmed !== undefined ? req.body.isConfirmed : existingBooking.isConfirmed,
  };

  const user = updatedBooking.user;
  const userBookings = bookingsStore[user];
  const bookingIndex = userBookings.findIndex((b) => b.date === existingBooking.date && b.service === existingBooking.service);
  if (bookingIndex === -1) return res.status(404).json({ error: 'Booking not found in user store' });

  userBookings[bookingIndex] = updatedBooking;
  bookingsStore[user] = userBookings;

  console.log('Server: Updated booking:', updatedBooking);

  res.status(200).json(updatedBooking);
});

app.delete('/api/bookings/:index', authenticateToken, (req, res) => {
  if (req.user.phone !== ADMIN_PHONE) return res.status(403).json({ error: 'Forbidden' });
  const index = parseInt(req.params.index);
  const allBookings = Object.values(bookingsStore).flat();
  if (isNaN(index) || index < 0 || index >= allBookings.length) return res.status(404).json({ error: 'Booking not found' });
  const bookingToDelete = allBookings[index];
  const user = bookingToDelete.user;
  bookingsStore[user] = bookingsStore[user].filter((b) => !(b.date === bookingToDelete.date && b.service === bookingToDelete.service));
  res.status(204).send();
});

app.get('/api/orders', authenticateToken, (req, res) => {
  if (req.user.phone === ADMIN_PHONE) return res.status(200).json(Object.values(ordersStore).flat());
  res.status(200).json(ordersStore[req.user.phone] || []);
});

app.post('/api/orders', authenticateToken, (req, res) => {
  const { items, totalCost } = req.body;
  if (!items || !totalCost) return res.status(400).json({ error: 'Missing required fields' });
  const sanitizedOrder = {
    user: req.user.phone,
    items: items.map(item => ({
      name: sanitize(item.name),
      cost: sanitize(item.cost),
      ...(item.date && { date: sanitize(item.date) }),
      ...(item.duration && { duration: parseInt(item.duration, 10) }),
      ...(item.menu && { menu: item.menu.map(sanitize) }),
    })),
    totalCost: sanitize(totalCost),
    orderTime: new Date().toISOString(),
    status: 'Pending'
  };
  if (!ordersStore[req.user.phone]) ordersStore[req.user.phone] = [];
  ordersStore[req.user.phone].push(sanitizedOrder);
  console.log('Server: Saved order:', sanitizedOrder);
  res.status(201).json(sanitizedOrder);
});

app.put('/api/orders/:index', authenticateToken, async (req, res) => {
  const index = parseInt(req.params.index);
  if (req.user.phone !== ADMIN_PHONE) {
    if (!ordersStore[req.user.phone] || index < 0 || index >= ordersStore[req.user.phone].length) {
      return res.status(404).json({ error: 'Order not found' });
    }
    ordersStore[req.user.phone][index] = { ...ordersStore[req.user.phone][index], ...req.body };
    return res.status(200).json(ordersStore[req.user.phone][index]);
  }

  const allOrders = Object.values(ordersStore).flat();
  if (isNaN(index) || index < 0 || index >= allOrders.length) {
    return res.status(404).json({ error: 'Order not found' });
  }
  const orderToUpdate = allOrders[index];
  const user = orderToUpdate.user;
  const userOrders = ordersStore[user];
  const orderIndex = userOrders.findIndex(
    (o) => o.orderTime === orderToUpdate.orderTime && o.totalCost === orderToUpdate.totalCost
  );
  if (orderIndex === -1) return res.status(404).json({ error: 'Order not found in user store' });

  userOrders[orderIndex] = { ...userOrders[orderIndex], ...req.body };
  ordersStore[user] = userOrders;

  console.log('Server: Updated order:', userOrders[orderIndex]);
  res.status(200).json(userOrders[orderIndex]);
});

app.get('/api/services', authenticateToken, (req, res) => res.status(200).json(servicesStore));

app.put('/api/services/:serviceName', authenticateToken, (req, res) => {
  if (req.user.phone !== ADMIN_PHONE) return res.status(403).json({ error: 'Forbidden' });
  const { serviceName } = req.params;
  const { price, nameRu, nameEn, descRu, descEn } = req.body;
  if (!servicesStore[serviceName]) return res.status(404).json({ error: 'Service not found' });

  servicesStore[serviceName] = {
    price: price ? sanitize(price) : servicesStore[serviceName].price,
    name: {
      ru: nameRu ? sanitize(nameRu) : servicesStore[serviceName].name.ru,
      en: nameEn ? sanitize(nameEn) : servicesStore[serviceName].name.en,
    },
    description: {
      ru: descRu ? sanitize(descRu) : servicesStore[serviceName].description.ru,
      en: descEn ? sanitize(descEn) : servicesStore[serviceName].description.en,
    },
  };
  res.status(200).json(servicesStore[serviceName]);
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/assets/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'), { maxAge: '1h' });
});

app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

const server = app.listen(3001, () => console.log('Server running on port 3001'));
server.setTimeout(60000);

process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('Server closed.');
    process.exit(0);
  });
});