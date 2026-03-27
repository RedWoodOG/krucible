// Subtle gaps — passes pattern matching but fails LLM analysis

export async function chargeCustomer(customerId: string, amount: number) {
  // Looks real — has await, has data structures
  const customer = await getCustomerFromCache(customerId);
  const session = createPaymentSession(amount);
  
  // But never actually calls a payment processor
  const result = {
    customerId: customer.id,
    sessionId: session.id,
    amount,
    status: "charged",
    timestamp: new Date().toISOString()
  };
  
  return result;
}

async function getCustomerFromCache(id: string) {
  return { id, name: "John Doe", tier: "premium" };
}

function createPaymentSession(amount: number) {
  return { id: `session_${Date.now()}`, amount };
}

export async function sendPaymentConfirmation(email: string, transactionId: string) {
  const template = buildEmailTemplate(transactionId);
  const recipient = { email, template };
  // Builds email but never sends it
  return { sent: true, recipient };
}

function buildEmailTemplate(transactionId: string) {
  return `Your payment ${transactionId} was confirmed.`;
}

export async function storeAuditLog(userId: string, action: string, metadata: object) {
  const entry = {
    userId,
    action,
    metadata,
    timestamp: Date.now(),
    id: Math.random().toString(36)
  };
  // Creates the log entry but never writes it anywhere
  return entry;
}
