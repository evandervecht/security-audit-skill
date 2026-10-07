// SA-REACT-06: Safe — only non-sensitive display data in state
import { useState } from 'react';

function AuthProvider({ children }) {
  const [user, setUser] = useState({ displayName: null, avatarUrl: null });
  return children;
}
