import CoreNFC
import Foundation

/// APDUs to a FIDO key held to the iPhone. The Rust core calls `transmit`
/// synchronously from a background queue; CoreNFC answers on the session's
/// queue, so a semaphore bridges the two.
final class TagLink: NfcLink, @unchecked Sendable {
    private let tag: NFCISO7816Tag

    init(tag: NFCISO7816Tag) { self.tag = tag }

    func transmit(apdu: Data) throws -> Data {
        guard let cmd = NFCISO7816APDU(data: apdu) else {
            throw FpError.Other(detail: "Malformed APDU")
        }
        let done = DispatchSemaphore(value: 0)
        var result: Result<Data, Error> = .failure(FpError.Link(detail: "No answer from the key"))
        tag.sendCommand(apdu: cmd) { data, sw1, sw2, error in
            if let error = error {
                result = .failure(FpError.Link(detail: "The key moved away from the iPhone. Hold it still until FidoParole is done. (\(error.localizedDescription))"))
            } else {
                result = .success(data + Data([sw1, sw2]))
            }
            done.signal()
        }
        if done.wait(timeout: .now() + 20) == .timedOut {
            throw FpError.Link(detail: "The key did not answer in time")
        }
        return try result.get()
    }
}

/// One NFC operation: show the system sheet, wait for a key, run `work`
/// while it stays on the phone, then close the sheet.
final class NFCKeyReader: NSObject, NFCTagReaderSessionDelegate, @unchecked Sendable {
    private var session: NFCTagReaderSession?
    private var work: ((KeyLink, NFCTagReaderSession) -> Void)?
    private var failed: ((Error) -> Void)?
    private let queue = DispatchQueue(label: "fidoparole.nfc")
    private let workQueue = DispatchQueue(label: "fidoparole.nfc.work")

    static var available: Bool { NFCTagReaderSession.readingAvailable }

    func run<T: Sendable>(prompt: String, listener: KeyListener?, _ body: @escaping (KeyLink) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<T, Error>) in
            var finished = false
            let finish: (Result<T, Error>) -> Void = { r in
                guard !finished else { return }
                finished = true
                cont.resume(with: r)
            }
            self.failed = { finish(.failure($0)) }
            self.work = { [weak self] link, session in
                guard let self else { return }
                self.workQueue.async {
                    do {
                        let value = try body(link)
                        session.alertMessage = "Done"
                        session.invalidate()
                        finish(.success(value))
                    } catch {
                        session.invalidate(errorMessage: describe(error))
                        finish(.failure(error))
                    }
                }
            }
            guard let s = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: queue) else {
                finish(.failure(FpError.Other(detail: "NFC is not available on this iPhone")))
                return
            }
            s.alertMessage = prompt
            self.session = s
            s.begin()
        }
    }

    func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {}

    func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        let e = error as? NFCReaderError
        if e?.code == .readerSessionInvalidationErrorUserCanceled {
            failed?(CancellationError())
        } else if e?.code != .readerSessionInvalidationErrorFirstNDEFTagRead {
            failed?(FpError.Link(detail: error.localizedDescription))
        }
        self.session = nil
    }

    func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        guard let first = tags.first, case .iso7816(let iso) = first else {
            session.alertMessage = "That's not a FIDO security key. Try your key."
            session.restartPolling()
            return
        }
        session.connect(to: first) { [weak self] error in
            guard let self else { return }
            if let error = error {
                session.invalidate(errorMessage: "Couldn't connect to the key: \(error.localizedDescription)")
                return
            }
            session.alertMessage = "Keep holding the key…"
            self.workQueue.async {
                do {
                    let link = try KeyLink.nfc(link: TagLink(tag: iso), listener: nil)
                    self.work?(link, session)
                } catch {
                    session.invalidate(errorMessage: describe(error))
                    self.failed?(error)
                }
            }
        }
    }
}

func describe(_ error: Error) -> String {
    if let e = error as? FpError {
        switch e {
        case .Key(_, let detail), .Link(let detail), .Other(let detail):
            return detail.prefix(1).uppercased() + detail.dropFirst()
        }
    }
    return error.localizedDescription
}
