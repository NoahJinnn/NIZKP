use k256::{
    ProjectivePoint, Scalar, U256,
};
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
    fn prove(sid: &str, pid: u32, x: Scalar, y: ProjectivePoint) -> Self {
        let r = generate_random_number();
        let t = ProjectivePoint::GENERATOR * &r;
        let c = Self::hash_points(sid, pid, &[ProjectivePoint::GENERATOR, y, t]);
        let s = r + c * x;
        Self::new(t, s)
    }
    fn verify(&self, sid: &str, pid: u32, y: ProjectivePoint) -> bool {
        let c = Self::hash_points(sid, pid, &[ProjectivePoint::GENERATOR, y, self.t]);
        let lhs = ProjectivePoint::GENERATOR * &self.s;
        let rhs = &self.t + &(&y * &c);
        lhs == rhs
    }
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
    let pid: u32 = 1;
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
