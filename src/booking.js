const fs = require('fs');
const path = require('path');

const BOOKINGS_PATH = path.join(__dirname, 'bookings.json');

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

// Each booking is expected as: { date: 'YYYY-MM-DD', time: 'HH:MM', durationMinutes }
function computeAvailableSlots(businessProfile, bookings, dateString) {
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

  const dayBookings = bookings.filter((booking) => booking.date === dateString);

  const isOccupied = (start, end) =>
    dayBookings.some((booking) => {
      const bookingStart = parseTimeToMinutes(booking.time);
      const bookingEnd = bookingStart + booking.durationMinutes;
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

function confirmBooking(businessProfile, bookings, date, time, serviceName, customerId) {
  const service = businessProfile.services.find((s) => s.name === serviceName);

  if (!service) {
    throw new Error(`Unknown service: ${serviceName}`);
  }

  const booking = {
    date,
    time,
    durationMinutes: service.durationMinutes,
    service: serviceName,
    customerId
  };

  bookings.push(booking);

  fs.writeFileSync(BOOKINGS_PATH, JSON.stringify(bookings, null, 2));

  return booking;
}

module.exports = { computeAvailableSlots, confirmBooking };
