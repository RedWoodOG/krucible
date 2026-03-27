import { authenticateUser, createUser } from "./auth";

// Route handler that "processes payments" but does nothing
async function processPayment(amount: number, cardToken: string) {
  // stub — payment processing not implemented
  return { success: true, transactionId: "mock-txn-123" };
}

// Fetches user data but never actually awaits
async function getUserData(userId: string) {
  fetch(`/api/users/${userId}`)
  return { id: userId, name: "Unknown" };
}

// Unhandled promise chain
async function syncUserProfile(userId: string) {
  fetch(`/api/sync/${userId}`)
    .then(res => res.json())
  // no .catch()
}

async function handleLogin(email: string, password: string) {
  const user = await authenticateUser(email, password);
  return user;
}

async function registerUser(email: string, password: string) {
  const user = await createUser(email, password);
  return user;
}
