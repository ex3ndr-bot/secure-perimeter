//
//  AttestationVerifier.swift
//  SecurePerimeter
//
//  Attestation quote verification for AMD SEV-SNP and Intel TDX.
//  Parses hardware attestation reports and verifies against expected measurements.
//

import Foundation

// MARK: - Report Structures

/// AMD SEV-SNP attestation report structure
/// Reference: AMD SEV-SNP ABI Specification, Table 21
public struct SNPReport {
    // Report structure offsets
    static let totalSize = 1184
    
    public let version: UInt32
    public let guestSvn: UInt32
    public let policy: UInt64
    public let familyId: Data       // 16 bytes
    public let imageId: Data        // 16 bytes
    public let vmpl: UInt32
    public let measurement: Data    // 48 bytes - LAUNCH_DIGEST
    public let hostData: Data       // 32 bytes
    public let reportData: Data     // 64 bytes - user-provided data
    public let reportId: Data       // 32 bytes
    public let chipId: Data         // 64 bytes
    public let signature: Data      // 512 bytes - ECDSA signature
    
    /// Parse an SNP report from raw bytes
    public init(data: Data) throws {
        guard data.count >= Self.totalSize else {
            throw AttestationError.reportTooShort(data.count, expected: Self.totalSize)
        }
        
        version = data.withUnsafeBytes { $0.load(fromByteOffset: 0, as: UInt32.self).littleEndian }
        guard version == 1 || version == 2 else {
            throw AttestationError.unsupportedVersion(Int(version))
        }
        
        guestSvn = data.withUnsafeBytes { $0.load(fromByteOffset: 4, as: UInt32.self).littleEndian }
        policy = data.withUnsafeBytes { $0.load(fromByteOffset: 8, as: UInt64.self).littleEndian }
        familyId = data.subdata(in: 16..<32)
        imageId = data.subdata(in: 32..<48)
        vmpl = data.withUnsafeBytes { $0.load(fromByteOffset: 48, as: UInt32.self).littleEndian }
        measurement = data.subdata(in: 144..<192)
        hostData = data.subdata(in: 192..<224)
        reportData = data.subdata(in: 80..<144)
        reportId = data.subdata(in: 320..<352)
        chipId = data.subdata(in: 416..<480)
        signature = data.subdata(in: 672..<1184)
    }
}

/// Intel TDX attestation report structure
/// Reference: Intel TDX Module v1.5 ABI Specification
public struct TDXReport {
    static let totalSize = 584
    
    public let teeTcbSvn: Data      // 16 bytes
    public let mrSeam: Data         // 48 bytes
    public let mrSignerSeam: Data   // 48 bytes
    public let tdAttributes: UInt64
    public let mrTd: Data           // 48 bytes - Initial TD measurement
    public let mrConfigId: Data     // 48 bytes
    public let mrOwner: Data        // 48 bytes
    public let rtmr0: Data          // 48 bytes - Runtime measurement register
    public let rtmr1: Data          // 48 bytes
    public let rtmr2: Data          // 48 bytes
    public let rtmr3: Data          // 48 bytes
    public let reportData: Data     // 64 bytes
    
    /// Parse a TDX report from raw bytes
    public init(data: Data) throws {
        guard data.count >= Self.totalSize else {
            throw AttestationError.reportTooShort(data.count, expected: Self.totalSize)
        }
        
        teeTcbSvn = data.subdata(in: 0..<16)
        mrSeam = data.subdata(in: 16..<64)
        mrSignerSeam = data.subdata(in: 64..<112)
        tdAttributes = data.withUnsafeBytes { $0.load(fromByteOffset: 120, as: UInt64.self).littleEndian }
        mrTd = data.subdata(in: 136..<184)
        mrConfigId = data.subdata(in: 184..<232)
        mrOwner = data.subdata(in: 232..<280)
        rtmr0 = data.subdata(in: 328..<376)
        rtmr1 = data.subdata(in: 376..<424)
        rtmr2 = data.subdata(in: 424..<472)
        rtmr3 = data.subdata(in: 472..<520)
        reportData = data.subdata(in: 520..<584)
    }
}

// MARK: - Verifier

/// Attestation verification result
public struct VerificationResult {
    public let valid: Bool
    public let attestationType: AttestationType
    public let errors: [String]
    public let warnings: [String]
    public let parsedReport: Any?  // SNPReport or TDXReport
    
    public enum AttestationType {
        case sevSnp
        case tdx
        case unknown
    }
}

/// Expected measurements for verification
public struct ExpectedMeasurements {
    /// AMD SEV-SNP launch measurement (48 bytes hex)
    public var snpMeasurement: Data?
    /// Intel TDX MRTD (48 bytes hex)
    public var tdxMrTd: Data?
    /// Intel TDX RTMR0 (48 bytes hex)
    public var tdxRtmr0: Data?
    /// Expected prefix of report data
    public var reportDataPrefix: Data?
    /// Minimum TCB version
    public var minTcbVersion: UInt32?
    
    public init(
        snpMeasurement: Data? = nil,
        tdxMrTd: Data? = nil,
        tdxRtmr0: Data? = nil,
        reportDataPrefix: Data? = nil,
        minTcbVersion: UInt32? = nil
    ) {
        self.snpMeasurement = snpMeasurement
        self.tdxMrTd = tdxMrTd
        self.tdxRtmr0 = tdxRtmr0
        self.reportDataPrefix = reportDataPrefix
        self.minTcbVersion = minTcbVersion
    }
}

/// Attestation verifier
///
/// ## Overview
/// `AttestationVerifier` parses and verifies hardware attestation quotes from
/// AMD SEV-SNP and Intel TDX Trusted Execution Environments. It performs:
///
/// 1. Quote format detection (SNP vs TDX)
/// 2. Binary report parsing according to vendor specs
/// 3. Measurement comparison against expected values
/// 4. Hardware signature verification (in production - requires vendor CA certs)
///
/// ## Usage
/// ```swift
/// let verifier = AttestationVerifier()
///
/// // Fetch expected measurements from Rekor
/// let expected = try await RekorClient().fetchMeasurements(
///     imageDigest: "sha256:abc123..."
/// )
///
/// // Verify attestation quote
/// let result = try verifier.verify(
///     quote: attestationData,
///     expected: expected
/// )
///
/// if result.valid {
///     print("Attestation verified!")
/// } else {
///     print("Verification failed: \(result.errors)")
/// }
/// ```
///
/// ## Implementation Notes
/// - Hardware signature verification requires AMD VCEK / Intel QE certificates
/// - VCEK certs can be fetched from AMD Key Distribution Service (KDS)
/// - Intel uses Provisioning Certification Service (PCS) for QE certs
/// - In production, implement full certificate chain validation
///
public class AttestationVerifier {
    
    public init() {}
    
    // MARK: - Public API
    
    /// Detect attestation type from quote bytes
    public func detectType(_ quote: Data) -> VerificationResult.AttestationType {
        guard quote.count >= 4 else { return .unknown }
        
        let version = quote.withUnsafeBytes {
            $0.load(fromByteOffset: 0, as: UInt32.self).littleEndian
        }
        
        // AMD SEV-SNP reports start with version 1 or 2
        if (version == 1 || version == 2) && quote.count >= SNPReport.totalSize {
            return .sevSnp
        }
        
        // TDX reports have different structure
        if quote.count >= TDXReport.totalSize {
            return .tdx
        }
        
        return .unknown
    }
    
    /// Verify attestation quote against expected measurements
    ///
    /// - Parameters:
    ///   - quote: Raw attestation quote bytes from server
    ///   - expected: Expected measurements to verify against
    /// - Returns: Verification result with errors/warnings
    public func verify(
        quote: Data,
        expected: ExpectedMeasurements
    ) -> VerificationResult {
        var errors: [String] = []
        var warnings: [String] = []
        var parsedReport: Any?
        
        let attestationType = detectType(quote)
        
        switch attestationType {
        case .sevSnp:
            do {
                let report = try SNPReport(data: quote)
                parsedReport = report
                
                // Verify measurement
                if let expectedMeasurement = expected.snpMeasurement {
                    if report.measurement != expectedMeasurement {
                        errors.append("SNP measurement does not match expected value")
                    }
                } else {
                    warnings.append("No expected SNP measurement provided")
                }
                
                // Verify report data prefix
                if let prefix = expected.reportDataPrefix {
                    if !report.reportData.starts(with: prefix) {
                        errors.append("Report data does not match expected prefix")
                    }
                }
                
                // TODO: Verify ECDSA signature against AMD VCEK certificate
                // 1. Extract chip ID from report
                // 2. Fetch VCEK cert from AMD KDS: https://kdsintf.amd.com/vcek/v1/{product}/{hwid}
                // 3. Validate cert chain up to AMD root CA
                // 4. Verify signature using VCEK public key
                warnings.append("Hardware signature verification not yet implemented")
                
            } catch {
                errors.append("Failed to parse SNP report: \(error)")
            }
            
        case .tdx:
            do {
                let report = try TDXReport(data: quote)
                parsedReport = report
                
                // Verify MRTD
                if let expectedMrTd = expected.tdxMrTd {
                    if report.mrTd != expectedMrTd {
                        errors.append("TDX MRTD does not match expected value")
                    }
                } else {
                    warnings.append("No expected TDX MRTD provided")
                }
                
                // Verify RTMR0
                if let expectedRtmr0 = expected.tdxRtmr0 {
                    if report.rtmr0 != expectedRtmr0 {
                        errors.append("TDX RTMR0 does not match expected value")
                    }
                }
                
                // Verify report data prefix
                if let prefix = expected.reportDataPrefix {
                    if !report.reportData.starts(with: prefix) {
                        errors.append("Report data does not match expected prefix")
                    }
                }
                
                // TODO: Verify Intel QE signature
                // 1. Parse ECDSA quote structure (outer wrapper around TD report)
                // 2. Fetch QE identity from Intel PCS
                // 3. Validate certificate chain to Intel root CA
                // 4. Verify quote signature
                warnings.append("Hardware signature verification not yet implemented")
                
            } catch {
                errors.append("Failed to parse TDX report: \(error)")
            }
            
        case .unknown:
            errors.append("Unable to detect attestation type from quote format")
        }
        
        return VerificationResult(
            valid: errors.isEmpty,
            attestationType: attestationType,
            errors: errors,
            warnings: warnings,
            parsedReport: parsedReport
        )
    }
}

// MARK: - Rekor Client

/// Client for querying Rekor transparency log
///
/// Fetches expected measurements for container images from the Sigstore
/// Rekor transparency log. Measurements are embedded in SLSA provenance
/// attestations signed during the build process.
///
public class RekorClient {
    private let baseURL = "https://rekor.sigstore.dev"
    
    public init() {}
    
    /// Fetch expected measurements for an image digest
    ///
    /// - Parameter imageDigest: Container image digest (sha256:...)
    /// - Returns: Expected measurements if found, nil otherwise
    public func fetchMeasurements(imageDigest: String) async throws -> ExpectedMeasurements? {
        // Search for entries by hash
        let searchURL = URL(string: "\(baseURL)/api/v1/index/retrieve")!
        var request = URLRequest(url: searchURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let hash = imageDigest.contains(":") 
            ? imageDigest 
            : "sha256:\(imageDigest)"
        
        request.httpBody = try JSONEncoder().encode(["hash": hash])
        
        let (data, response) = try await URLSession.shared.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw RekorError.invalidResponse
        }
        
        if httpResponse.statusCode == 404 {
            return nil
        }
        
        guard httpResponse.statusCode == 200 else {
            throw RekorError.requestFailed(httpResponse.statusCode)
        }
        
        // Parse UUID list and fetch entries
        let uuids = try JSONDecoder().decode([String].self, from: data)
        
        for uuid in uuids {
            if let entry = try await fetchEntry(uuid: uuid),
               let measurements = extractMeasurements(from: entry) {
                return measurements
            }
        }
        
        return nil
    }
    
    private func fetchEntry(uuid: String) async throws -> [String: Any]? {
        let url = URL(string: "\(baseURL)/api/v1/log/entries/\(uuid)")!
        let (data, _) = try await URLSession.shared.data(from: url)
        
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        
        return json
    }
    
    private func extractMeasurements(from entry: [String: Any]) -> ExpectedMeasurements? {
        // Parse in-toto attestation and extract measurements from SLSA provenance
        // This is a stub - actual implementation needs to decode base64 body,
        // parse the in-toto envelope, and extract measurements from predicate
        return nil
    }
}

// MARK: - Errors

public enum AttestationError: Error {
    case reportTooShort(Int, expected: Int)
    case unsupportedVersion(Int)
    case invalidSignature
    case measurementMismatch
}

public enum RekorError: Error {
    case invalidResponse
    case requestFailed(Int)
    case entryNotFound
}

// MARK: - Utilities

extension Data {
    /// Convert to hex string
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
    
    /// Initialize from hex string
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex
        
        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }
        
        self = data
    }
}
