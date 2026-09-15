require('dotenv').config();

const PROVIDER = (process.env.AI_PROVIDER || 'anthropic').toLowerCase();

function formatSlotList(slots) {
  return slots.length > 0 ? slots.join(', ') : 'none';
}

function buildSystemPrompt(businessProfile, availableSlots) {
  const { businessName, voice, hours, services, escalateIfCustomerMentions } = businessProfile;

  return `You are replying to customer messages on behalf of ${businessName}, a real small business.

VOICE:
- Tone: ${voice.tone}
- Reply length: ${voice.maxReplyLength}
- Emoji: ${voice.useEmoji ? 'use occasionally, naturally' : 'do not use emoji'}
- NEVER use these phrases (they sound like an AI bot, not a real staff member): ${voice.avoidPhrases.join(', ')}
- Match this style, shown here as real examples of how this business actually talks:
${voice.sampleReplies.map(r => `  - "${r}"`).join('\n')}

BUSINESS INFO:
- Hours: ${JSON.stringify(hours)}
- Services offered: ${services.map(s => `${s.name} ($${s.price}, ${s.durationMinutes} min)`).join('; ')}

AVAILABLE SLOTS:
- Today is ${availableSlots.todayDate}. Today's available slots: ${formatSlotList(availableSlots.today)}
- Tomorrow is ${availableSlots.tomorrowDate}. Tomorrow's available slots: ${formatSlotList(availableSlots.tomorrow)}
- Only offer times from these lists. Never invent or guess a time that isn't listed.

RULES:
- Sound like a real person texting back, not customer support. Be brief. Real staff don't over-explain.
- If the customer wants to book, confirm the specific service and propose a specific time from the available slots above.
- If the customer message mentions any of: ${escalateIfCustomerMentions.join(', ')} — do NOT try to resolve it yourself. Respond briefly and say a real person will follow up, and flag this conversation for human review.
- Never say you are an AI unless directly and explicitly asked.
- When the customer clearly confirms a specific time AND service (e.g. "yeah 2:30 works" after being offered it), end your reply with a hidden marker line on its own new line, in exactly this format: [BOOKING_CONFIRMED: date=YYYY-MM-DD, time=HH:MM, service=<service name>] — using the real date (from "Today is"/"Tomorrow is" above), the confirmed time, and the exact service name. This marker is never shown to the customer, so do not mention it or refer to it in the customer-facing part of the reply.
- If no booking is being confirmed, do not include the marker line at all.
- Output ONLY the reply text (plus the marker line when a booking is confirmed). No preamble, no explanation, no quotation marks around it.`;
}

async function callAnthropic(systemPrompt, conversationHistory, incomingMessage) {
  const Anthropic = require('@anthropic-ai/sdk');
  const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

  const messages = [...conversationHistory, { role: 'user', content: incomingMessage }];

  const response = await client.messages.create({
    model: 'claude-sonnet-5',
    max_tokens: 200,
    system: systemPrompt,
    messages
  });

  return response.content
    .filter(block => block.type === 'text')
    .map(block => block.text)
    .join('\n')
    .trim();
}

async function callGemini(systemPrompt, conversationHistory, incomingMessage) {
  const { GoogleGenAI } = require('@google/genai');
  const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

  const contents = [
    ...conversationHistory.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }]
    })),
    { role: 'user', parts: [{ text: incomingMessage }] }
  ];

  const response = await ai.models.generateContent({
    model: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
    contents,
    config: { systemInstruction: systemPrompt }
  });

  return response.text.trim();
}

async function callGroq(systemPrompt, conversationHistory, incomingMessage) {
  const Groq = require('groq-sdk');
  const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

  const messages = [
    { role: 'system', content: systemPrompt },
    ...conversationHistory.map(m => ({
      role: m.role === 'assistant' ? 'assistant' : 'user',
      content: m.content
    })),
    { role: 'user', content: incomingMessage }
  ];

  const completion = await groq.chat.completions.create({
    model: process.env.GROQ_MODEL || 'openai/gpt-oss-120b',
    messages,
    temperature: 0.7,
    max_tokens: 512
  });

  return (completion.choices[0]?.message?.content ?? '').trim();
}

async function generateReply(businessProfile, conversationHistory, incomingMessage, availableSlots) {
  const lowerMsg = incomingMessage.toLowerCase();
  const needsHumanReview = businessProfile.escalateIfCustomerMentions.some(term =>
    lowerMsg.includes(term.toLowerCase())
  );

  const systemPrompt = buildSystemPrompt(businessProfile, availableSlots);

  let reply;
  if (PROVIDER === 'groq') {
    reply = await callGroq(systemPrompt, conversationHistory, incomingMessage);
  } else if (PROVIDER === 'gemini') {
    reply = await callGemini(systemPrompt, conversationHistory, incomingMessage);
  } else {
    reply = await callAnthropic(systemPrompt, conversationHistory, incomingMessage);
  }

  return { reply, needsHumanReview };
}

function computeTypingDelayMs(replyText) {
  const base = 1200;
  const perChar = 35;
  const jitter = Math.random() * 1500;
  return Math.min(base + replyText.length * perChar + jitter, 9000);
}

module.exports = { generateReply, computeTypingDelayMs, buildSystemPrompt };