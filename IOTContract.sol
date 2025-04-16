pragma solidity >= 0.8.11 <= 0.8.11;

// Smart contract to manage patient details
contract IOTContract {
    string public patient_details;

    // Constructor
    constructor() public {
        patient_details = "";
    }

    // Function to save patient data in Blockchain
    function savePatientData(string memory pd) public {
        patient_details = pd;
    }

    // Function to get patient data from Blockchain
    function getPatientData() public view returns (string memory) {
        return patient_details;
    }
}
