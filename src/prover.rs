// Most of this file is modified from source codes of [Matter Labs](https://github.com/matter-labs)
use anyhow::format_err;
use bellman_ce::pairing::Engine;
use bellman_ce::{
    bn256::Bn256,
    kate_commitment::{Crs, CrsForMonomialForm},
    plonk::is_satisfied,
    plonk::is_satisfied_using_one_shot_check,
    plonk::{
        better_cs::cs::PlonkCsWidth4WithNextStepParams, commitments::transcript::keccak_transcript::RollingKeccakTranscript,
        make_verification_key, prove_by_steps, setup, transpile, transpile_with_gates_count, verify, SetupPolynomials,
        TranspilationVariant, VerificationKey,
    },
    Circuit, ScalarEngine,
};
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Instant;
use std::{fs::remove_file, fs::File, path::Path, thread};

use crate::circom_circuit::{r1cs_from_json_file, witness_from_json_file, CircomCircuit};
use crate::proofsys_type::ProofSystem;

pub const SETUP_MIN_POW2: u32 = 20;
pub const SETUP_MAX_POW2: u32 = 26;

pub struct PlonkVerificationKey<E: Engine>(VerificationKey<E, PlonkCsWidth4WithNextStepParams>);

fn base_universal_setup_dir() -> Result<PathBuf, anyhow::Error> {
    let mut dir = PathBuf::new();
    // root is used by default for provers
    dir.push("keys");
    dir.push("setup");
    anyhow::ensure!(dir.exists(), "Universal setup dir does not exits");
    Ok(dir)
}

fn get_universal_setup_file_buff_reader(setup_file_name: &str) -> Result<BufReader<File>, anyhow::Error> {
    let setup_file = {
        let mut path = base_universal_setup_dir()?;
        path.push(&setup_file_name);
        File::open(path).map_err(|e| format_err!("Failed to open universal setup file {}, err: {}", setup_file_name, e))?
    };
    Ok(BufReader::with_capacity(1 << 29, setup_file))
}

/// Returns universal setup in the monomial form of the given power of two (range: SETUP_MIN_POW2..=SETUP_MAX_POW2). Checks if file exists
pub fn get_universal_setup_monomial_form<E: Engine>(power_of_two: u32) -> Result<Crs<E, CrsForMonomialForm>, anyhow::Error> {
    anyhow::ensure!(
        (SETUP_MIN_POW2..=SETUP_MAX_POW2).contains(&power_of_two),
        "setup power of two is not in the correct range"
    );
    let setup_file_name = format!("setup_2^{}.key", power_of_two);
    let mut buf_reader = get_universal_setup_file_buff_reader(&setup_file_name)?;
    Ok(Crs::<E, CrsForMonomialForm>::read(&mut buf_reader).map_err(|e| format_err!("Failed to read Crs from setup file: {}", e))?)
}

pub struct SetupForStepByStepProver<E: Engine> {
    setup_polynomials: SetupPolynomials<E, PlonkCsWidth4WithNextStepParams>,
    hints: Vec<(usize, TranspilationVariant)>,
    setup_power_of_two: u32,
    key_monomial_form: Option<Crs<E, CrsForMonomialForm>>,
}

impl<E: Engine> SetupForStepByStepProver<E> {
    pub fn prepare_setup_for_step_by_step_prover<C: Circuit<E> + Clone>(circuit: C) -> Result<Self, anyhow::Error> {
        let hints = transpile(circuit.clone())?;
        let setup_polynomials = setup(circuit, &hints)?;
        let size = setup_polynomials.n.next_power_of_two().trailing_zeros();
        let setup_power_of_two = std::cmp::max(size, SETUP_MIN_POW2); // for exit circuit
        let key_monomial_form = Some(get_universal_setup_monomial_form(setup_power_of_two)?);
        Ok(SetupForStepByStepProver {
            setup_power_of_two,
            setup_polynomials,
            hints,
            key_monomial_form,
        })
    }

    pub fn gen_step_by_step_proof_using_prepared_setup<C: Circuit<E> + Clone>(
        &self,
        circuit: C,
        vk: &PlonkVerificationKey<E>,
    ) -> Result<(), anyhow::Error> {
        let timer = Instant::now();
        let proof = prove_by_steps::<_, _, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(
            circuit,
            &self.hints,
            &self.setup_polynomials,
            None,
            self.key_monomial_form.as_ref().expect("Setup should have universal setup struct"),
        )?;
        log::info!("Proving takes {:?}", timer.elapsed());
        log::info!("Proof generated");

        let proof_path = "testdata/poseidon/proof.bin";
        let writer = File::create(proof_path).unwrap();
        proof.write(writer).unwrap();
        log::info!("Proof saved to {}", proof_path);

        let valid = verify::<_, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(&proof, &vk.0)?;
        anyhow::ensure!(valid, "proof for block is invalid");
        Ok(())
    }
}
