/**
 * Unit tests for asyncHandler middleware
 */

import { asyncHandler } from '../../../src/middlewares/asyncHandler.js';

describe('asyncHandler', () => {
  it('should call next with no arguments when async function succeeds', async () => {
    const mockFn = jest.fn(async (req, res, next) => {
      next();
    });
    const handler = asyncHandler(mockFn);
    
    const req = {};
    const res = {};
    const next = jest.fn();
    
    await handler(req, res, next);
    
    expect(mockFn).toHaveBeenCalledWith(req, res, next);
    expect(next).toHaveBeenCalledWith();
  });

  it('should call next with error when async function throws', async () => {
    const error = new Error('Test error');
    const mockFn = jest.fn(async () => {
      throw error;
    });
    const handler = asyncHandler(mockFn);
    
    const req = {};
    const res = {};
    const next = jest.fn();
    
    await handler(req, res, next);
    
    expect(next).toHaveBeenCalledWith(error);
  });

  it('should call next with error when async function rejects', async () => {
    const error = new Error('Async error');
    const mockFn = jest.fn(async () => {
      throw error; // Throw instead of returning rejected promise
    });
    const handler = asyncHandler(mockFn);
    
    const req = {};
    const res = {};
    const next = jest.fn();
    
    await handler(req, res, next);
    
    expect(next).toHaveBeenCalledWith(error);
  });

  it('should pass req, res, next to the wrapped function', async () => {
    const mockFn = jest.fn(async (req, res, next) => {
      req.testProp = 'test';
      next();
    });
    const handler = asyncHandler(mockFn);
    
    const req = {};
    const res = {};
    const next = jest.fn();
    
    await handler(req, res, next);
    
    expect(req.testProp).toBe('test');
    expect(mockFn).toHaveBeenCalledWith(req, res, next);
  });
});
