/**
 * CertOne Java SDK: a typed, thread-safe client of the CertOne control-plane REST API.
 *
 * <p>Entry point: {@link ai.certkor.certone.CertOneClient}. Submissions return {@link
 * ai.certkor.certone.CheckResult}; scans are {@link ai.certkor.certone.ScanRun}; verdict summaries
 * are {@link ai.certkor.certone.Report}; full report documents and attestations are Jackson {@link
 * com.fasterxml.jackson.databind.JsonNode} trees. Every failure is a {@link
 * ai.certkor.certone.CertOneException}.
 */
package ai.certkor.certone;
