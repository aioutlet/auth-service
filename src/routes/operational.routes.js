import express from 'express';
import { health, readiness, liveness, metrics } from '../controllers/operational.controller.js';

const router = express.Router();

/**
 * Operational endpoints for monitoring, health checks, and observability
 * These endpoints are typically used by:
 * - Load balancers
 * - Kubernetes probes (liveness, readiness)
 * - Monitoring systems (Prometheus, Datadog, etc.)
 * - DevOps tools
 */

/**
 * @route   GET /health
 * @desc    Main health check endpoint - checks overall service health
 * @access  Public (no auth required)
 */
router.get('/health', health);

/**
 * @route   GET /health/ready
 * @desc    Readiness probe - checks if service is ready to receive traffic
 * @access  Public (no auth required)
 */
router.get('/health/ready', readiness);

/**
 * @route   GET /health/live
 * @desc    Liveness probe - checks if service is alive (not deadlocked)
 * @access  Public (no auth required)
 */
router.get('/health/live', liveness);

/**
 * @route   GET /metrics
 * @desc    Metrics endpoint - exposes service metrics for monitoring
 * @access  Public (no auth required)
 */
router.get('/metrics', metrics);

export default router;
