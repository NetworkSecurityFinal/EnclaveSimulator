# EnclaveSimulator

The following is and Enclave simulator. With this simulator you can see both the process of:
- Remote Attestation
- An attack on an Encalve caused by state malleaubility

### How to run the Remote Attestation:
- TODO
### How to run the Attack Simulation:
1. Navigate to Enclave.java (located in isv.enclave package)
2. Find the empty constructor
```
protected Enclave()
{
  setAuthCount(0);
  setGeneralInfo(new HashSet<>());
  setCreateInterrupt(false);
};
  ```
3. Replace ```setCreateInterrupt(false)``` with ```setCreateInterrupt(true)```
4. Run Enclave.java, located in the isv.enclave package (run through an editor like Eclipse or through the command line)
5. Run ISVClient.java
- the first time an interrupt should occur, which messes with the state of the enclave
6. Run ISVClient.java one more time
- the second ecall will successfully initiate the attack
