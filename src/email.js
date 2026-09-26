const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

// onboarding@resend.dev only delivers to the email address associated with
// this Resend account — any other recipient gets a 403 — until a custom
// domain is verified. See:
// https://resend.com/docs/knowledge-base/403-error-resend-dev-domain
// Swap this for a verified-domain address once one is added.
const FROM_ADDRESS = 'Autumn Assistant <onboarding@resend.dev>';

// Local copy of server.js's escapeHtml — kept small and self-contained
// rather than requiring server.js, which is the app entry point and isn't
// designed to be imported elsewhere (same reasoning voice.js already
// applies to formatDateYYYYMMDD).
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

async function sendRecoveryEmail(toEmail, businessName, dashboardUrl) {
  const { data, error } = await resend.emails.send({
    from: FROM_ADDRESS,
    to: [toEmail],
    subject: 'Your Autumn Assistant dashboard link',
    html: `
      <p>Hi,</p>
      <p>Here's the dashboard link for <strong>${escapeHtml(businessName)}</strong>:</p>
      <p><a href="${escapeHtml(dashboardUrl)}">${escapeHtml(dashboardUrl)}</a></p>
      <p>If you didn't request this, you can safely ignore this email.</p>
    `
  });

  if (error) {
    throw new Error(`Failed to send recovery email: ${error.message}`);
  }

  return data;
}

module.exports = { sendRecoveryEmail };
