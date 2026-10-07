// SA-REACT-06: Sensitive data stored in React state
import { useState } from 'react';

function AuthProvider({ children }) {
  const [auth, setAuth] = useState({ token: null, refreshToken: null, user: null });
  return children;
}
