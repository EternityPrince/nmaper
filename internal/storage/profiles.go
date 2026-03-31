package storage

import (
	"context"
	"database/sql"
	"encoding/json"

	"nmaper/internal/snapshot"
)

func persistHostProfile(ctx context.Context, tx *sql.Tx, hostObservationID int64, profile snapshot.HostProfile) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM vulnerability_findings WHERE host_observation_id = ? AND service_observation_id IS NULL`, hostObservationID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM management_surfaces WHERE host_observation_id = ? AND service_observation_id IS NULL`, hostObservationID); err != nil {
		return err
	}
	for _, finding := range profile.Vulnerabilities {
		if err := insertFinding(ctx, tx, hostObservationID, nil, finding); err != nil {
			return err
		}
	}
	for _, surface := range profile.Management {
		if err := insertManagement(ctx, tx, hostObservationID, nil, surface); err != nil {
			return err
		}
	}
	return nil
}

func persistServiceProfile(ctx context.Context, tx *sql.Tx, hostObservationID, serviceObservationID int64, profile snapshot.ServiceProfile) error {
	if err := deleteServiceProfile(ctx, tx, serviceObservationID); err != nil {
		return err
	}
	if profile.TLS != nil {
		versionsJSON, err := marshalStrings(profile.TLS.Versions)
		if err != nil {
			return err
		}
		ciphersJSON, err := marshalStrings(profile.TLS.Ciphers)
		if err != nil {
			return err
		}
		weakJSON, err := marshalStrings(profile.TLS.WeakCiphers)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO tls_fingerprints
			 (service_observation_id, subject, issuer, not_before, not_after, sha256, versions_json, ciphers_json, weak_ciphers_json)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			serviceObservationID,
			nullString(profile.TLS.Subject),
			nullString(profile.TLS.Issuer),
			nullString(profile.TLS.NotBefore),
			nullString(profile.TLS.NotAfter),
			nullString(profile.TLS.SHA256),
			versionsJSON,
			ciphersJSON,
			weakJSON,
		); err != nil {
			return err
		}
	}
	if profile.SSH != nil {
		hostKeysJSON, err := marshalStrings(profile.SSH.HostKeys)
		if err != nil {
			return err
		}
		algorithmsJSON, err := marshalStrings(profile.SSH.Algorithms)
		if err != nil {
			return err
		}
		weakJSON, err := marshalStrings(profile.SSH.WeakAlgorithms)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO ssh_fingerprints
			 (service_observation_id, host_keys_json, algorithms_json, weak_algorithms_json)
			 VALUES (?, ?, ?, ?)`,
			serviceObservationID,
			hostKeysJSON,
			algorithmsJSON,
			weakJSON,
		); err != nil {
			return err
		}
	}
	if profile.HTTP != nil {
		methodsJSON, err := marshalStrings(profile.HTTP.Methods)
		if err != nil {
			return err
		}
		authJSON, err := marshalStrings(profile.HTTP.AuthSchemes)
		if err != nil {
			return err
		}
		pathsJSON, err := marshalStrings(profile.HTTP.Paths)
		if err != nil {
			return err
		}
		securityJSON, err := marshalStrings(profile.HTTP.SecurityHeaders)
		if err != nil {
			return err
		}
		headersJSON, err := marshalStrings(profile.HTTP.Headers)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO http_fingerprints
			 (service_observation_id, title, server, methods_json, auth_schemes_json, paths_json, security_headers_json, headers_json)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			serviceObservationID,
			nullString(profile.HTTP.Title),
			nullString(profile.HTTP.Server),
			methodsJSON,
			authJSON,
			pathsJSON,
			securityJSON,
			headersJSON,
		); err != nil {
			return err
		}
	}
	if profile.SMB != nil {
		protocolsJSON, err := marshalStrings(profile.SMB.Protocols)
		if err != nil {
			return err
		}
		sharesJSON, err := marshalStrings(profile.SMB.Shares)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(
			ctx,
			`INSERT INTO smb_fingerprints
			 (service_observation_id, os, workgroup, protocols_json, shares_json)
			 VALUES (?, ?, ?, ?, ?)`,
			serviceObservationID,
			nullString(profile.SMB.OS),
			nullString(profile.SMB.Workgroup),
			protocolsJSON,
			sharesJSON,
		); err != nil {
			return err
		}
	}
	for _, finding := range profile.Vulnerabilities {
		if err := insertFinding(ctx, tx, hostObservationID, &serviceObservationID, finding); err != nil {
			return err
		}
	}
	for _, surface := range profile.Management {
		if err := insertManagement(ctx, tx, hostObservationID, &serviceObservationID, surface); err != nil {
			return err
		}
	}
	return nil
}

func deleteServiceProfile(ctx context.Context, tx *sql.Tx, serviceObservationID int64) error {
	statements := []string{
		`DELETE FROM tls_fingerprints WHERE service_observation_id = ?`,
		`DELETE FROM ssh_fingerprints WHERE service_observation_id = ?`,
		`DELETE FROM http_fingerprints WHERE service_observation_id = ?`,
		`DELETE FROM smb_fingerprints WHERE service_observation_id = ?`,
		`DELETE FROM vulnerability_findings WHERE service_observation_id = ?`,
		`DELETE FROM management_surfaces WHERE service_observation_id = ?`,
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement, serviceObservationID); err != nil {
			return err
		}
	}
	return nil
}

func insertFinding(ctx context.Context, tx *sql.Tx, hostObservationID int64, serviceObservationID *int64, finding snapshot.VulnerabilityFinding) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO vulnerability_findings
		 (host_observation_id, service_observation_id, script_id, identifier, title, severity, state, evidence)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hostObservationID,
		nullableInt64(serviceObservationID),
		finding.ScriptID,
		nullString(finding.Identifier),
		nullString(finding.Title),
		nullString(finding.Severity),
		nullString(finding.State),
		nullString(finding.Evidence),
	)
	return err
}

func insertManagement(ctx context.Context, tx *sql.Tx, hostObservationID int64, serviceObservationID *int64, surface snapshot.ManagementSurface) error {
	_, err := tx.ExecContext(
		ctx,
		`INSERT INTO management_surfaces
		 (host_observation_id, service_observation_id, category, label, port, protocol, exposure, detail)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		hostObservationID,
		nullableInt64(serviceObservationID),
		surface.Category,
		nullString(surface.Label),
		surface.Port,
		surface.Protocol,
		nullString(surface.Exposure),
		nullString(surface.Detail),
	)
	return err
}

func marshalStrings(items []string) (string, error) {
	body, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	return string(body), nil
}
