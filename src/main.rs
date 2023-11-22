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
    fn to_dict(&self) -> serde_json::Value {
        serde_json::json!({
            "t": self.t.to_affine().to_bytes().to_vec(),
            "s": self.s.to_bytes().to_vec(),
        })
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
    }
