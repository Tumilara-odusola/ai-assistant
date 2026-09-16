const { pool } = require('./db');

const DAY_KEYS = ['sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat'];

function parseTimeToMinutes(timeStr) {
  const [hours, minutes] = timeStr.split(':').map(Number);
  return hours * 60 + minutes;
}

function minutesToTimeString(totalMinutes) {
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
}

// `bookings` is kept as a parameter for call-site compatibility but is
// unused — availability is now read from the Postgres `bookings` table.
async function computeAvailableSlots(businessProfile, bookings, dateString) {
  const dayKey = DAY_KEYS[new Date(`${dateString}T00:00:00`).getDay()];
  const hoursRange = businessProfile.hours[dayKey];

  if (!hoursRange || hoursRange === 'closed') {
    return [];
  }

  const [openStr, closeStr] = hoursRange.split('-');
  const openMinutes = parseTimeToMinutes(openStr);
  const closeMinutes = parseTimeToMinutes(closeStr);

  const slotMinutes = Math.min(
    ...businessProfile.services.map((service) => service.durationMinutes)
  );

  const { rows: dayBookings } = await pool.query(
    'SELECT time, duration_minutes FROM bookings WHERE date = $1',
    [dateString]
  );

  const isOccupied = (start, end) =>
    dayBookings.some((booking) => {
      const bookingStart = parseTimeToMinutes(booking.time);
      const bookingEnd = bookingStart + booking.duration_minutes;
      return start < bookingEnd && end > bookingStart;
    });

  const slots = [];

  for (
    let start = openMinutes;
    start + slotMinutes <= closeMinutes;
    start += slotMinutes
  ) {
    if (!isOccupied(start, start + slotMinutes)) {
      slots.push(minutesToTimeString(start));
    }
  }

  return slots;
}

// `bookings` is kept as a parameter for call-site compatibility but is
// unused — the booking is now persisted to the Postgres `bookings` table.
async function confirmBooking(businessProfile, bookings, date, time, serviceName, customerId) {
  const service = businessProfile.services.find((s) => s.name === serviceName);

  if (!service) {
    throw new Error(`Unknown service: ${serviceName}`);
  }

  await pool.query(
    `INSERT INTO bookings (date, time, duration_minutes, service, customer_id)
     VALUES ($1, $2, $3, $4, $5)`,
    [date, time, service.durationMinutes, serviceName, customerId]
  );

  return {
    date,
    time,
    durationMinutes: service.durationMinutes,
    service: serviceName,
    customerId
  };
}

module.exports = { computeAvailableSlots, confirmBooking };
