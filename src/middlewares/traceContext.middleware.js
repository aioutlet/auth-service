/**
 * Middleware to extract W3C Trace Context from Dapr
 * Dapr automatically propagates traceparent header with format:
 * version-traceId-spanId-flags (e.g., 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01)
 * 
 * This middleware extracts the traceId and spanId for use in application logs,
 * enabling correlation with Dapr's distributed tracing.
 */
const traceContextMiddleware = (req, res, next) => {
  const traceparent = req.headers['traceparent'];
  
  if (traceparent) {
    const parts = traceparent.split('-');
    if (parts.length === 4) {
      req.traceId = parts[1];  // 32-character trace ID
      req.spanId = parts[2];   // 16-character span ID
    }
  }
  
  // Fallback if no traceparent (shouldn't happen with Dapr, but good practice)
  req.traceId = req.traceId || 'no-trace';
  req.spanId = req.spanId || 'no-span';
  
  // Add to response headers for debugging/observability
  res.setHeader('X-Trace-ID', req.traceId);
  
  // Add to locals for access in templates/views if needed
  res.locals.traceId = req.traceId;
  res.locals.spanId = req.spanId;
  
  next();
};

// Export all functions
export { traceContextMiddleware };
