import jwt from 'jsonwebtoken';

describe('JWT Debug', () => {
  it('should test JWT directly', () => {
    const secret = 'test-secret';
    const payload = { id: '123' };
    
    const token = jwt.sign(payload, secret, { expiresIn: '15m' });
    expect(typeof token).toBe('string');
    
    const decoded = jwt.verify(token, secret);
    expect(decoded.id).toBe('123');
  });
  
  it('should test with process.env', () => {
    process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
    const payload = { id: '123' };
    
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '15m' });
    expect(typeof token).toBe('string');
  });
});