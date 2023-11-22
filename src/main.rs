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
  }
fn main() {
    let x = generate_random_number();
    println!("x: {:?}", x);
    }
