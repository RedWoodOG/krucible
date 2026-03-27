// Fake auth module — classic AI slop

export async function authenticateUser(email: string, password: string) {
  // TODO: implement actual authentication
  return { id: "123", email, token: "fake-token" };
}

export async function createUser(email: string, password: string) {
  // This claims to save a user but just returns a mock
  const user = { id: "mock-id", email, createdAt: new Date() };
  return user;
}

export async function saveUserToDatabase(user: any) {
  // Placeholder — will implement later
  console.log("saving user...", user);
  return true;
}

export function validateToken(token: string) {
  // FIXME: actually verify the JWT
  return token.length > 10;
}

export async function sendWelcomeEmail(user: any) {
  // TODO: connect to email provider
  console.log("would send email to", user.email);
}

function neverCalledHelper() {
  return "I exist but nobody calls me";
}

function anotherDeadFunction() {
  const x = 1 + 1;
  return x;
}
