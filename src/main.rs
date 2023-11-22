use k256::{
    elliptic_curve::{
        group::GroupEncoding,
        ops::Reduce,
        sec1::{Coordinates, ToEncodedPoint},
        Field,
    },
    ProjectivePoint, Scalar, U256,
};
use sha2::{Digest, Sha256};

fn generate_random_number() -> Scalar {
    let mut rng = rand::thread_rng();
    Scalar::random(&mut rng)
}

#[derive(Debug)]
struct DLogProof {
    t: ProjectivePoint,
    s: Scalar,
}

impl DLogProof {
    fn new(t: ProjectivePoint, s: Scalar) -> Self {
        Self { t, s }
    }

    /// Computes a hash of the given session id, point id, and points.
    ///
    /// This function takes a session id, a point id, and a vector of points, and computes a hash
    /// of these inputs. The hash is then reduced to a scalar in the field of the elliptic curve.
    ///
    /// # Arguments
    ///
    /// * `sid` - The session id.
    /// * `pid` - The id of the point.
    /// * `points` - The points to be hashed.
    ///
    /// # Returns
    ///
    /// A `Scalar` representing the hash of the inputs.
    ///
    /// # Example
    ///
    /// ```
    /// # use zk_proof::DLogProof;
    /// # use k256::ProjectivePoint;
    /// let sid = "sid";
    /// let pid = 1;
    /// let points = vec![ProjectivePoint::generator(); 3];
    /// let hash = DLogProof::hash_points(sid, pid, &points);
    /// println!("{}", hash);
    /// ```
    fn hash_points(sid: &str, pid: u32, points: &[ProjectivePoint]) -> Scalar {
        let mut hasher = Sha256::new();
        hasher.update(sid.as_bytes());
        hasher.update(&pid.to_be_bytes());
        for point in points {
            hasher.update(&point.to_affine().to_bytes());
        }
        let result: &[u8] = &hasher.finalize();

        let e = <Scalar as Reduce<U256>>::reduce_bytes(result.into());
        e
    }

    /// Generates a proof that the prover knows the discrete logarithm of `y`.
    ///
    /// The prover generates a random number `r`, computes `t = r*G` and `c = H(sid, pid, G, y, t)`,
    /// and then computes `s = r + c*x` and returns the proof `(t, s)`.
    ///
    /// # Arguments
    ///
    /// * `sid` - The session id.
    /// * `pid` - The id of the prover.
    /// * `x` - The secret number.
    /// * `y` - The point that we want to prove that we know the discrete logarithm of.
    /// * `base_point` - The base point of the group.
    ///
    /// # Returns
    ///
    /// A `DLogProof` struct containing the `t` and `s` values.
    ///
    /// # Example
    ///
    /// ```
    /// # use zk_proof::DLogProof;
    /// # use zk_proof::generate_random_number;
    /// # use k256::ProjectivePoint;
    /// let sid = "sid";
    /// let pid = 1;
    /// let x = generate_random_number();
    /// let y = &x * &ProjectivePoint::generator();
    /// let dlog_proof = DLogProof::prove(sid, pid, x, y);
    /// println!("{}, {}", dlog_proof.t.x(), dlog_proof.t.y());
    /// println!("{}", dlog_proof.s);
    /// ```
    fn prove(sid: &str, pid: u32, x: Scalar, y: ProjectivePoint) -> Self {
        let r = generate_random_number();
        let t = ProjectivePoint::GENERATOR * &r;
        let c = Self::hash_points(sid, pid, &[ProjectivePoint::GENERATOR, y, t]);
        let s = r + c * x;
        Self::new(t, s)
    }

    /// Verifies that the point `t` equals `s` times the base point plus the hash of the inputs times `y`.
    ///
    /// # Arguments
    ///
    /// * `sid` - The session id.
    /// * `pid` - The id of the prover.
    /// * `y` - The public key.
    /// * `base_point` - The base point of the group.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the point `t` is the correct sum.
    ///
    /// # Example
    ///
    /// ```
    /// # use zk_proof::DLogProof;
    /// # use zk_proof::generate_random_number;
    /// # use k256::ProjectivePoint;
    /// let sid = "sid";
    /// let pid = 1;
    /// let x = generate_random_number();
    /// let y = &x * &ProjectivePoint::generator();
    /// let dlog_proof = DLogProof::prove(sid, pid, x, y);
    /// assert!(dlog_proof.verify(sid, pid, y));
    /// ```
    fn verify(&self, sid: &str, pid: u32, y: ProjectivePoint) -> bool {
        let c = Self::hash_points(sid, pid, &[ProjectivePoint::GENERATOR, y, self.t]);
        let lhs = ProjectivePoint::GENERATOR * &self.s;
        let rhs = &self.t + &(&y * &c);
        lhs == rhs
    }

    /// Converts the `DLogProof` instance into a JSON object.
    ///
    /// This method serializes the `DLogProof` instance into a `serde_json::Value` object.
    /// The `t` field of the `DLogProof` is converted to affine coordinates and then to bytes,
    /// and the `s` field is directly converted to bytes. Both are then stored in a JSON object.
    ///
    /// # Returns
    ///
    /// A `serde_json::Value` representing the `DLogProof` instance.
    ///
    /// # Example
    ///
    /// ```
    /// # use zk_proof::DLogProof;
    /// let dlog_proof = DLogProof::new(/* parameters */);
    /// let json = dlog_proof.to_dict();
    /// println!("{}", json);
    /// ```
    fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "t": self.t.to_affine().to_bytes().to_vec(),
            "s": self.s.to_bytes().to_vec(),
        })
    }

    #[allow(dead_code)]
    fn from_dict(data: serde_json::Value) -> Self {
        let t = data["t"].clone();
        let t_str = t.to_string();
        let t_bytes = t_str.as_bytes();
        let t = ProjectivePoint::from_bytes(t_bytes.into()).unwrap();

        let s = data["s"].clone();
        let s_str = s.to_string();
        let s_bytes = s_str.as_bytes();
        let s = <Scalar as Reduce<U256>>::reduce_bytes(s_bytes.into());
        Self::new(t, s)
    }
}

fn main() {
    let sid = "sid";
    let pid = 1;

    let x = generate_random_number();
    println!("x: {:?}", x);
    let y = ProjectivePoint::GENERATOR * &x;

    let start_proof = std::time::Instant::now();
    let dlog_proof = DLogProof::prove(sid, pid, x, y);
    println!(
        "Proof computation time: {} ms",
        start_proof.elapsed().as_millis()
    );

    let enc_point = dlog_proof.t.to_encoded_point(false);
    match enc_point.coordinates() {
        Coordinates::Uncompressed { x, y } => {
            println!("x: {:?}, y: {:?}", x, y);
        }
        _ => panic!("Invalid point encoding"),
    }
    println!("{}", dlog_proof.to_dict()["s"]);

    let start_verify = std::time::Instant::now();
    let result = dlog_proof.verify(sid, pid, y);
    println!(
        "Verify computation time: {} ms",
        start_verify.elapsed().as_millis()
    );

    if result {
        println!("DLOG proof is correct");
    } else {
        println!("DLOG proof is not correct");
    }
}
