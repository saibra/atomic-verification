;; Atomic Verification - Zero-Knowledge Identity Platform

;; Error Constants
(define-constant ERR_UNAUTHORIZED (err u1))
(define-constant ERR_INVALID_SKILL (err u2))
(define-constant ERR_INVALID_PROOF (err u3))
(define-constant ERR_INSUFFICIENT_STAKE (err u4))
(define-constant ERR_VERIFIER_NOT_FOUND (err u5))
(define-constant ERR_SKILL_EXPIRED (err u6))
(define-constant ERR_INVALID_THRESHOLD (err u7))
(define-constant ERR_DUPLICATE_VERIFICATION (err u8))
(define-constant ERR_INVALID_MERKLE_PROOF (err u9))
(define-constant ERR_INVALID_COMMITMENT (err u10))
(define-constant ERR_REPUTATION_TOO_LOW (err u11))
(define-constant ERR_VERIFICATION_REQUEST_NOT_FOUND (err u12))
(define-constant ERR_SKILL_ALREADY_EXISTS (err u13))
(define-constant ERR_DEADLINE_PASSED (err u14))
(define-constant ERR_INSUFFICIENT_BALANCE (err u15))

;; Data Variables
(define-data-var contract-owner principal tx-sender)
(define-data-var skill-id-nonce uint u0)
(define-data-var verification-request-nonce uint u0)
(define-data-var minimum-stake uint u1000)
(define-data-var skill-decay-rate uint u5) ;; percentage per year
(define-data-var base-reputation uint u100)

;; Data Maps
(define-map skills
    uint
    {
        name: (string-ascii 64),
        category: (string-ascii 32),
        decay-rate: uint,
        verification-threshold: uint,
        is-active: bool,
        created-at: uint
    }
)

(define-map user-skill-proofs
    {user: principal, skill-id: uint}
    {
        commitment-hash: (buff 32),
        merkle-root: (buff 32),
        confidence-score: uint,
        last-verified: uint,
        verifier: principal,
        stake-amount: uint,
        proof-valid-until: uint
    }
)

(define-map verifier-profiles
    principal
    {
        reputation-score: uint,
        total-verifications: uint,
        successful-verifications: uint,
        total-staked: uint,
        is-approved: bool
    }
)

(define-map verification-requests
    uint
    {
        requester: principal,
        skill-requirements: (list 10 uint),
        confidence-threshold: uint,
        reputation-threshold: uint,
        deadline: uint,
        is-active: bool,
        reward-amount: uint
    }
)

(define-map skill-compositions
    uint
    {
        parent-skill: uint,
        required-subskills: (list 5 uint),
        composition-logic: (string-ascii 32) ;; "AND", "OR", "THRESHOLD"
    }
)

(define-map user-reputation
    principal
    {
        base-score: uint,
        verification-bonus: uint,
        stake-penalties: uint,
        last-updated: uint
    }
)

(define-map temporal-skill-weights
    {skill-id: uint, time-period: uint}
    {
        weight-multiplier: uint,
        decay-applied: bool
    }
)

;; Private Functions
(define-private (verify-merkle-path (proof-element (buff 32)) (current-hash (buff 32)))
    (keccak256 (concat current-hash proof-element))
)

(define-private (calculate-reputation (user principal))
    (match (map-get? user-reputation user)
        reputation
        (+ (get base-score reputation) 
           (- (get verification-bonus reputation) (get stake-penalties reputation)))
        (var-get base-reputation)
    )
)

(define-private (is-skill-expired (skill-proof {commitment-hash: (buff 32), merkle-root: (buff 32), confidence-score: uint, last-verified: uint, verifier: principal, stake-amount: uint, proof-valid-until: uint}))
    (> block-height (get proof-valid-until skill-proof))
)

;; Owner Functions
(define-public (set-contract-owner (new-owner principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
        (ok (var-set contract-owner new-owner))
    )
)

(define-public (set-minimum-stake (new-minimum uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
        (asserts! (> new-minimum u0) ERR_INVALID_THRESHOLD)
        (ok (var-set minimum-stake new-minimum))
    )
)

(define-public (approve-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
        (match (map-get? verifier-profiles verifier)
            existing-profile (ok (map-set verifier-profiles verifier 
                (merge existing-profile {is-approved: true})))
            (ok (map-set verifier-profiles verifier {
                reputation-score: (var-get base-reputation),
                total-verifications: u0,
                successful-verifications: u0,
                total-staked: u0,
                is-approved: true
            }))
        )
    )
)

(define-public (revoke-verifier (verifier principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
        (match (map-get? verifier-profiles verifier)
            existing-profile (ok (map-set verifier-profiles verifier 
                (merge existing-profile {is-approved: false})))
            ERR_VERIFIER_NOT_FOUND
        )
    )
)

;; Public Functions
(define-public (register-skill (name (string-ascii 64)) (category (string-ascii 32)) (threshold uint))
    (let ((skill-id (+ (var-get skill-id-nonce) u1)))
        (asserts! (> threshold u0) ERR_INVALID_THRESHOLD)
        (asserts! (< threshold u101) ERR_INVALID_THRESHOLD)
        (asserts! (> (len name) u0) ERR_INVALID_SKILL)
        
        (map-set skills skill-id {
            name: name,
            category: category,
            decay-rate: (var-get skill-decay-rate),
            verification-threshold: threshold,
            is-active: true,
            created-at: block-height
        })
        (var-set skill-id-nonce skill-id)
        (ok skill-id)
    )
)

(define-public (submit-skill-proof 
    (skill-id uint) 
    (commitment (buff 32)) 
    (merkle-root (buff 32))
    (confidence uint)
    (stake-amount uint))
    (let (
        (verifier-profile (unwrap! (map-get? verifier-profiles tx-sender) ERR_VERIFIER_NOT_FOUND))
        (skill-info (unwrap! (map-get? skills skill-id) ERR_INVALID_SKILL))
    )
        (asserts! (get is-approved verifier-profile) ERR_UNAUTHORIZED)
        (asserts! (>= stake-amount (var-get minimum-stake)) ERR_INSUFFICIENT_STAKE)
        (asserts! (and (>= confidence u1) (<= confidence u100)) ERR_INVALID_THRESHOLD)
        (asserts! (get is-active skill-info) ERR_INVALID_SKILL)
        (asserts! (not (is-eq commitment 0x00)) ERR_INVALID_COMMITMENT)
        
        ;; Check for duplicate verification
        (asserts! (is-none (map-get? user-skill-proofs {user: tx-sender, skill-id: skill-id})) 
                  ERR_DUPLICATE_VERIFICATION)
        
        (try! (stx-transfer? stake-amount tx-sender (as-contract tx-sender)))
        
        (map-set user-skill-proofs 
            {user: tx-sender, skill-id: skill-id}
            {
                commitment-hash: commitment,
                merkle-root: merkle-root,
                confidence-score: confidence,
                last-verified: block-height,
                verifier: tx-sender,
                stake-amount: stake-amount,
                proof-valid-until: (+ block-height u52560) ;; ~1 year
            }
        )
        
        ;; Update verifier profile
        (map-set verifier-profiles tx-sender 
            (merge verifier-profile {
                total-verifications: (+ (get total-verifications verifier-profile) u1),
                total-staked: (+ (get total-staked verifier-profile) stake-amount)
            })
        )
        
        (ok true)
    )
)

(define-public (create-verification-request 
    (skill-requirements (list 10 uint))
    (confidence-threshold uint)
    (reputation-threshold uint)
    (deadline uint)
    (reward-amount uint))
    (let ((request-id (+ (var-get verification-request-nonce) u1)))
        (asserts! (> (len skill-requirements) u0) ERR_INVALID_SKILL)
        (asserts! (and (>= confidence-threshold u1) (<= confidence-threshold u100)) ERR_INVALID_THRESHOLD)
        (asserts! (> deadline block-height) ERR_DEADLINE_PASSED)
        (asserts! (> reward-amount u0) ERR_INVALID_THRESHOLD)
        
        (try! (stx-transfer? reward-amount tx-sender (as-contract tx-sender)))
        
        (map-set verification-requests request-id {
            requester: tx-sender,
            skill-requirements: skill-requirements,
            confidence-threshold: confidence-threshold,
            reputation-threshold: reputation-threshold,
            deadline: deadline,
            is-active: true,
            reward-amount: reward-amount
        })
        (var-set verification-request-nonce request-id)
        (ok request-id)
    )
)

(define-public (verify-skill-proof 
    (user principal)
    (skill-id uint)
    (merkle-proof (list 10 (buff 32)))
    (leaf-data (buff 32)))
    (let (
        (skill-proof (unwrap! (map-get? user-skill-proofs {user: user, skill-id: skill-id}) ERR_INVALID_PROOF))
        (verifier-profile (unwrap! (map-get? verifier-profiles tx-sender) ERR_VERIFIER_NOT_FOUND))
        (calculated-root (fold verify-merkle-path merkle-proof leaf-data))
    )
        (asserts! (get is-approved verifier-profile) ERR_UNAUTHORIZED)
        (asserts! (< block-height (get proof-valid-until skill-proof)) ERR_SKILL_EXPIRED)
        (asserts! (is-eq calculated-root (get merkle-root skill-proof)) ERR_INVALID_MERKLE_PROOF)
        
        ;; Update successful verification count
        (map-set verifier-profiles tx-sender 
            (merge verifier-profile {
                successful-verifications: (+ (get successful-verifications verifier-profile) u1)
            })
        )
        
        ;; Update user reputation
        (match (map-get? user-reputation user)
            existing-rep (map-set user-reputation user 
                (merge existing-rep {
                    verification-bonus: (+ (get verification-bonus existing-rep) u10),
                    last-updated: block-height
                }))
            (map-set user-reputation user {
                base-score: (var-get base-reputation),
                verification-bonus: u10,
                stake-penalties: u0,
                last-updated: block-height
            })
        )
        
        (ok true)
    )
)

(define-public (update-skill-temporal-weight (skill-id uint) (time-period uint) (weight uint))
    (begin
        (asserts! (is-some (map-get? skills skill-id)) ERR_INVALID_SKILL)
        (asserts! (and (>= weight u1) (<= weight u200)) ERR_INVALID_THRESHOLD)
        
        (map-set temporal-skill-weights 
            {skill-id: skill-id, time-period: time-period}
            {weight-multiplier: weight, decay-applied: false}
        )
        (ok true)
    )
)

(define-public (compose-skill 
    (parent-skill uint)
    (subskills (list 5 uint))
    (logic (string-ascii 32)))
    (begin
        (asserts! (is-some (map-get? skills parent-skill)) ERR_INVALID_SKILL)
        (asserts! (> (len subskills) u0) ERR_INVALID_SKILL)
        (asserts! (or (is-eq logic "AND") (or (is-eq logic "OR") (is-eq logic "THRESHOLD"))) ERR_INVALID_SKILL)
        
        (map-set skill-compositions parent-skill {
            parent-skill: parent-skill,
            required-subskills: subskills,
            composition-logic: logic
        })
        (ok true)
    )
)

(define-public (withdraw-stake (skill-id uint))
    (let (
        (skill-proof (unwrap! (map-get? user-skill-proofs {user: tx-sender, skill-id: skill-id}) ERR_INVALID_PROOF))
    )
        (asserts! (> block-height (get proof-valid-until skill-proof)) ERR_SKILL_EXPIRED)
        
        (try! (as-contract (stx-transfer? (get stake-amount skill-proof) tx-sender tx-sender)))
        
        (map-delete user-skill-proofs {user: tx-sender, skill-id: skill-id})
        (ok (get stake-amount skill-proof))
    )
)

(define-public (deactivate-skill (skill-id uint))
    (let (
        (skill-info (unwrap! (map-get? skills skill-id) ERR_INVALID_SKILL))
    )
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR_UNAUTHORIZED)
        
        (map-set skills skill-id 
            (merge skill-info {is-active: false}))
        (ok true)
    )
)

;; Read-Only Functions
(define-read-only (get-skill-info (skill-id uint))
    (map-get? skills skill-id)
)

(define-read-only (get-user-skill-proof (user principal) (skill-id uint))
    (map-get? user-skill-proofs {user: user, skill-id: skill-id})
)

(define-read-only (get-verifier-profile (verifier principal))
    (map-get? verifier-profiles verifier)
)

(define-read-only (get-verification-request (request-id uint))
    (map-get? verification-requests request-id)
)

(define-read-only (get-skill-composition (skill-id uint))
    (map-get? skill-compositions skill-id)
)

(define-read-only (get-user-reputation (user principal))
    (calculate-reputation user)
)

(define-read-only (get-temporal-weight (skill-id uint) (time-period uint))
    (map-get? temporal-skill-weights {skill-id: skill-id, time-period: time-period})
)

(define-read-only (get-contract-info)
    {
        owner: (var-get contract-owner),
        skill-count: (var-get skill-id-nonce),
        request-count: (var-get verification-request-nonce),
        minimum-stake: (var-get minimum-stake),
        decay-rate: (var-get skill-decay-rate),
        base-reputation: (var-get base-reputation)
    }
)

(define-read-only (is-skill-valid (user principal) (skill-id uint))
    (match (map-get? user-skill-proofs {user: user, skill-id: skill-id})
        skill-proof (not (is-skill-expired skill-proof))
        false
    )
)

(define-read-only (get-skill-confidence (user principal) (skill-id uint))
    (match (map-get? user-skill-proofs {user: user, skill-id: skill-id})
        skill-proof (some (get confidence-score skill-proof))
        none
    )
)