# """
# Assumption Made: Each voter would get a key to use from their local library or similar goverment building.
# Two verications need to be possible,
# 1: Individual Verifiability
#     Each voter can confirm that their vote has been recorded and counted correctly
# 2: Universal Verifiability
#     Anyone can verify that the final tally is correct based on published information

# chatGpt chat: https://chatgpt.com/share/68f29721-899c-800b-979d-09d5e253b0d1
# MIT open courseware https://ocw.mit.edu/courses/6-5630-advanced-topics-in-cryptography-fall-2023/pages/lecture-6-fiat-shamir-paradigm-and-zero-knowledge-proofs/
# Python used: 3.13.5 and buildin libraries
# """

import hashlib, secrets

p = 7919 #prime number modulus
g = 2 
q = p - 1 #group order for the prime

#hash inputs using SHA-256 (following Fiat-Shamir)
def H_int(*elements):
    h = hashlib.sha256()
    for e in elements:
        h.update(str(e).encode())
        h.update(b"|")
    return int.from_bytes(h.digest(), "big") % p

#A disjunctive ZKP that proves the ciphertext encrypts one of the values in choices
def prove_disjunction(publicKey, ciphertext, plaintext, encryptionRand, choices):
    cipher1, cipher2 = ciphertext
    n = len(choices)
    commitments = []
    e_vals = []
    z_vals = []
    simulated_sum = 0
    sim_data = {}
    for i, m in enumerate(choices):
        if m == plaintext: #actual vote
            s = secrets.randbelow(publicKey["q"]-1)+1
            a1 = pow(publicKey["g"], s, publicKey["p"])
            a2 = pow(publicKey["h"], s, publicKey["p"])
            commitments.append((a1, a2))
            sim_data["real_index"] = i
            sim_data["s_real"] = s
        else: #fake vote to ensure viewers don't know which one was chosen
            e_sim = secrets.randbelow(publicKey["q"]-1) + 1
            z_sim = secrets.randbelow(publicKey["q"]-1) + 1
            c1_inv_e = pow(cipher1, (-e_sim) % (publicKey["q"]), publicKey["p"])
            a1 = (pow(publicKey["g"], z_sim, publicKey["p"]) * c1_inv_e) % publicKey["p"]
            gm = pow(publicKey["g"], m, publicKey["p"])
            numerator = (cipher2 * pow(gm, -1, publicKey["p"])) % publicKey["p"]
            numerator_inv_e = pow(numerator, (-e_sim) % (publicKey["q"]), publicKey["p"])
            a2 = (pow(publicKey["h"], z_sim, publicKey["p"]) * numerator_inv_e) % publicKey["p"]
            commitments.append((a1, a2))
            e_vals[i] = e_sim
            z_vals[i] = z_sim
            simulated_sum = (simulated_sum + e_sim) % publicKey["q"]
    #Step 2: Compute global challenge using Fiat-Shamir
    flat = []
    flat.extend([publicKey["p"], publicKey["g"], publicKey["h"], cipher1, cipher2])
    for (a1, a2) in commitments:
        flat.extend([a1, a2])
    e = H_int(*flat)
    
    # Step 3: Set the real branch challenge so that sum(e_i) = e (mod q)
    real_i = sim_data["real_index"]
    e_real = (e - simulated_sum) % publicKey["q"]
    e_vals[real_i] = e_real
    
    # Step 4: Compute z for real branch: z = s_real + e_real * r  (mod q)
    s_real = sim_data["s_real"]
    z_real = (s_real + (e_real * encryptionRand)) % publicKey["q"]
    z_vals[real_i] = z_real

    # Step 2: Compute global challenge via Fiat-Shamir over all commitments and inputs
    # Include public parameters to bind proof to this instance.
    flat = []
    flat.extend([publicKey["p"], publicKey["g"], publicKey["h"], cipher1, cipher2])
    for (a1, a2) in commitments:
        flat.extend([a1, a2])
    e = H_int(*flat)
    
    # Step 3: Set the real branch challenge so that sum(e_i) = e (mod q)
    real_i = sim_data["real_index"]
    e_real = (e - simulated_sum) % publicKey["q"]
    e_vals[real_i] = e_real
    
    # Step 4: Compute z for real branch: z = s_real + e_real * r  (mod q)
    s_real = sim_data["s_real"]
    z_real = (s_real + (e_real * encryptionRand)) % publicKey["q"]
    z_vals[real_i] = z_real
    
    # The proof consists of (choices, commitments, e_vals, z_vals)
    proof = {
        "choices": choices,
        "commitments": commitments,
        "e_vals": e_vals,
        "z_vals": z_vals,
    }
    return proof

def verify_zkp(publicKey, ciphertext, proof):
    cipher1, cipher2 = ciphertext
    choices = proof["choices"]
    commitments = proof["commitments"]
    e_vals = proof["e_vals"]
    z_vals = proof["z_vals"]
    recomputed = []
    for i, m in enumerate(choices): #recompute commitments for each branch and then check the consistency
        e_i = e_vals % publicKey["q"]
        z_i = z_vals % publicKey["q"]
        cipher1_inv_e = pow(cipher1, (-e_i) % (publicKey["q"]), publicKey["p"])
        a1_check = (pow(publicKey["g"], z_i, publicKey["p"]) * cipher1_inv_e) % publicKey["p"]
        gm = pow(publicKey["g"], m, publicKey["p"])
        numerator = (cipher2 * pow(gm, -1, publicKey["p"])) % publicKey["p"]
        numerator_inv_e = pow(numerator, (-e_i) % (publicKey["q"]), publicKey["p"])
        a2_check = (pow(publicKey["h"], z_i, publicKey["p"]) * numerator_inv_e) % publicKey["p"]
        recomputed.append((a1_check, a2_check))
    for rc, given in zip(recomputed, commitments):
        if rc != given:
            print("Commitment mismatch on a branch")
            return False
    
    # Verify that sum(e_i) == H(params || commitments)
    flat = []
    flat.extend([publicKey["p"], publicKey["g"], publicKey["h"], cipher1, cipher2])
    for (a1, a2) in commitments:
        flat.extend([a1, a2])
    e = H_int(*flat)
    if sum(e_vals) % publicKey["q"] != e % publicKey["q"]:
        print("Challenge sum mismatch")
        return False
    return True

def step3_indiv_verify(voterHashed, ciphertext, proof, bulletinBoard, publicKey):
    found_entry = next((entry for entry in bulletinBoard if entry["voter_id"] == voterHashed), None)
    if not found_entry:
        return False
    
    valid_proof = verify_zkp(publicKey, tuple(found_entry["ciphertext"]), found_entry["proof"])
    if not valid_proof:
        return False 
    
    return True #if we reach here the ciphertext encrypts one valid choice

def step4_universal_verify(bulletinBoard, finalTallyCipher, decryptionProof, publicKey):
    print("Doing universal verification")
    for entry in bulletinBoard:
        if not verify_zkp(publicKey, tuple(entry["ciphertext"]), entry["proof"]):
            return False #last checked proof wasnt valid
    
    
    #this could be removed
    cipher1Total = 1
    cipher2Total = 1
    for entry in bulletinBoard:
        cipher1, cipher2 = entry["ciphertext"]
        cipher1Total = (cipher1Total * cipher1) % publicKey["p"]
        cipher2Total = (cipher2Total * cipher2) % publicKey["p"]

    if not verify_decryption(publicKey, (cipher1Total, cipher2Total), decryptionProof): #need to change this function to one that verifies the decryption
        return False
    return True 