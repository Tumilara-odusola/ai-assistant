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

async function computeAvailableSlots(businessProfile, businessId, dateString) {
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
    'SELECT time, duration_minutes FROM bookings WHERE date = $1 AND business_id = $2',
    [dateString, businessId]
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

async function confirmBooking(businessProfile, businessId, date, time, serviceName, customerId) {
  const service = businessProfile.services.find((s) => s.name === serviceName);

  if (!service) {
    throw new Error(`Unknown service: ${serviceName}`);
  }

  try {
    await pool.query(
      `INSERT INTO bookings (date, time, duration_minutes, service, customer_id, business_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [date, time, service.durationMinutes, serviceName, customerId, businessId]
    );
  } catch (err) {
    if (err.code === '23505') {
      const slotTakenError = new Error('SLOT_ALREADY_BOOKED');
      slotTakenError.code = 'SLOT_ALREADY_BOOKED';
      throw slotTakenError;
    }

    throw err;
  }

  return {
    date,
    time,
    durationMinutes: service.durationMinutes,
    service: serviceName,
    customerId,
    businessId
  };
}

module.exports = { computeAvailableSlots, confirmBooking };
