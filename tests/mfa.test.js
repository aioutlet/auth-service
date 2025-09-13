// Comprehensive tests for MFA controller
import { enableMFA, verifyMFA, disableMFA } from '../../src/controllers/mfa.controller.js';
import { createMockReqRes, createMockNext, createMockUser } from '../utils/testHelpers.js';
import speakeasy from 'speakeasy';
import MFA from '../../src/models/mfa.model.js';

// Mock dependencies
jest.mock('speakeasy');
jest.mock('../../src/models/mfa.model.js');

describe('MFA Controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('enableMFA', () => {
    it('should generate MFA secret and create new MFA record', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });
      const mockSecret = {
        base32: 'JBSWY3DPEHPK3PXP',
        otpauth_url: 'otpauth://totp/AIOutlet%20(test@example.com)?secret=JBSWY3DPEHPK3PXP',
      };

      speakeasy.generateSecret.mockReturnValue(mockSecret);
      MFA.findOne.mockResolvedValue(null);
      const mockMFASave = jest.fn().mockResolvedValue();
      MFA.mockImplementation(() => ({
        save: mockMFASave,
      }));

      await enableMFA(req, res);

      expect(speakeasy.generateSecret).toHaveBeenCalledWith({
        name: `AIOutlet (${user.email})`,
      });
      expect(MFA.findOne).toHaveBeenCalledWith({ user: user._id });
      expect(MFA).toHaveBeenCalledWith({
        user: user._id,
        secret: mockSecret.base32,
        enabled: false,
      });
      expect(mockMFASave).toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith({
        otpauth_url: mockSecret.otpauth_url,
        base32: mockSecret.base32,
      });
    });

    it('should update existing MFA record', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });
      const mockSecret = {
        base32: 'JBSWY3DPEHPK3PXP',
        otpauth_url: 'otpauth://totp/AIOutlet%20(test@example.com)?secret=JBSWY3DPEHPK3PXP',
      };
      const existingMFA = {
        secret: 'old-secret',
        enabled: true,
        save: jest.fn().mockResolvedValue(),
      };

      speakeasy.generateSecret.mockReturnValue(mockSecret);
      MFA.findOne.mockResolvedValue(existingMFA);

      await enableMFA(req, res);

      expect(existingMFA.secret).toBe(mockSecret.base32);
      expect(existingMFA.enabled).toBe(false);
      expect(existingMFA.save).toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith({
        otpauth_url: mockSecret.otpauth_url,
        base32: mockSecret.base32,
      });
    });

    it('should return 401 when user is not authenticated', async () => {
      const { req, res } = createMockReqRes(); // No user

      await enableMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Authentication required',
      });
    });

    it('should handle database save errors', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });
      const mockSecret = {
        base32: 'JBSWY3DPEHPK3PXP',
        otpauth_url: 'otpauth://totp/AIOutlet%20(test@example.com)?secret=JBSWY3DPEHPK3PXP',
      };

      speakeasy.generateSecret.mockReturnValue(mockSecret);
      MFA.findOne.mockResolvedValue(null);
      const mockMFASave = jest.fn().mockRejectedValue(new Error('Database error'));
      MFA.mockImplementation(() => ({
        save: mockMFASave,
      }));

      await expect(enableMFA(req, res)).rejects.toThrow('Database error');
    });

    it('should handle user without _id', async () => {
      const user = { email: 'test@example.com' }; // Missing _id
      const { req, res } = createMockReqRes({ user });

      await enableMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Authentication required',
      });
    });
  });

  describe('verifyMFA', () => {
    it('should verify valid MFA token and enable MFA', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({
        user,
        body: { token: '123456' },
      });
      const existingMFA = {
        secret: 'JBSWY3DPEHPK3PXP',
        enabled: false,
        save: jest.fn().mockResolvedValue(),
      };

      MFA.findOne.mockResolvedValue(existingMFA);
      speakeasy.totp.verify.mockReturnValue(true);

      await verifyMFA(req, res);

      expect(MFA.findOne).toHaveBeenCalledWith({ user: user._id });
      expect(speakeasy.totp.verify).toHaveBeenCalledWith({
        secret: existingMFA.secret,
        encoding: 'base32',
        token: '123456',
        window: 1,
      });
      expect(existingMFA.enabled).toBe(true);
      expect(existingMFA.save).toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith({
        message: 'MFA enabled successfully',
      });
    });

    it('should return 400 for invalid MFA token', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({
        user,
        body: { token: '123456' },
      });
      const existingMFA = {
        secret: 'JBSWY3DPEHPK3PXP',
        enabled: false,
        save: jest.fn(),
      };

      MFA.findOne.mockResolvedValue(existingMFA);
      speakeasy.totp.verify.mockReturnValue(false);

      await verifyMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Invalid MFA code',
      });
      expect(existingMFA.save).not.toHaveBeenCalled();
    });

    it('should return 401 when user is not authenticated', async () => {
      const { req, res } = createMockReqRes({
        body: { token: '123456' },
      });

      await verifyMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Token and authentication required',
      });
    });

    it('should return 400 when token is missing', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });

      await verifyMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Token and authentication required',
      });
    });

    it('should return 404 when MFA setup not found', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({
        user,
        body: { token: '123456' },
      });

      MFA.findOne.mockResolvedValue(null);

      await verifyMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith({
        error: 'MFA setup not found',
      });
    });

    it('should handle database errors', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({
        user,
        body: { token: '123456' },
      });

      MFA.findOne.mockRejectedValue(new Error('Database error'));

      await expect(verifyMFA(req, res)).rejects.toThrow('Database error');
    });

    it('should handle empty token string', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({
        user,
        body: { token: '' },
      });

      await verifyMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Token and authentication required',
      });
    });
  });

  describe('disableMFA', () => {
    it('should disable MFA successfully', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });
      const existingMFA = {
        enabled: true,
        save: jest.fn().mockResolvedValue(),
      };

      MFA.findOne.mockResolvedValue(existingMFA);

      await disableMFA(req, res);

      expect(MFA.findOne).toHaveBeenCalledWith({ user: user._id });
      expect(existingMFA.enabled).toBe(false);
      expect(existingMFA.save).toHaveBeenCalled();
      expect(res.json).toHaveBeenCalledWith({
        message: 'MFA disabled successfully',
      });
    });

    it('should return 401 when user is not authenticated', async () => {
      const { req, res } = createMockReqRes();

      await disableMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(401);
      expect(res.json).toHaveBeenCalledWith({
        error: 'Authentication required',
      });
    });

    it('should return 400 when MFA is not found', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });

      MFA.findOne.mockResolvedValue(null);

      await disableMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'MFA is not enabled',
      });
    });

    it('should return 400 when MFA is already disabled', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });
      const existingMFA = {
        enabled: false,
        save: jest.fn(),
      };

      MFA.findOne.mockResolvedValue(existingMFA);

      await disableMFA(req, res);

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith({
        error: 'MFA is not enabled',
      });
      expect(existingMFA.save).not.toHaveBeenCalled();
    });

    it('should handle database errors', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });

      MFA.findOne.mockRejectedValue(new Error('Database error'));

      await expect(disableMFA(req, res)).rejects.toThrow('Database error');
    });

    it('should handle save errors', async () => {
      const user = createMockUser();
      const { req, res } = createMockReqRes({ user });
      const existingMFA = {
        enabled: true,
        save: jest.fn().mockRejectedValue(new Error('Save failed')),
      };

      MFA.findOne.mockResolvedValue(existingMFA);

      await expect(disableMFA(req, res)).rejects.toThrow('Save failed');
    });
  });
});
