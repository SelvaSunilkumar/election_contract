// SPDX-License-Identifier: MIT

pragma solidity >=0.5.16;
pragma experimental ABIEncoderV2;

/*
Error Codes
200     -       ok
100     -       fail
107     -       Unauthorized Access
*/

contract Election {

    /*--------------------------------------------------------------------------- 
                    Super Admin Module
    -----------------------------------------------------------------------------*/
    uint private numberOfSuperAdmins = 0;
    bool private isDefaultAdminAdded = false;

    struct superAdmin {
        string name;
        string emailId;
        string username;
        bytes32 encUsername;
        bytes32 password;
        bool occupied;
        bool canDelete;
    }

    struct superAdminDetails {
        string name;
        string emailId;
        string username;
        string encUsername;
        string password;
    }

    superAdmin sAdmin;

    //store super admin details based on the hash value of encryptedUserName hash value
    mapping(bytes32 => superAdmin) private superAdminHashmap;
    mapping (uint=> bytes32) private superAdminsAccountDetails;
    mapping(bytes32 => string) private superAdminLoginLog;

    //get all details of Super admins
    function getAllSuperAdminDetails(string memory encUsername) public view returns(superAdmin[] memory) {

        if (isSuperAdminUsernameTaken(encUsername)) {
            superAdmin[] memory allDetails = new superAdmin[](numberOfSuperAdmins);
            for (uint i = 0; i < numberOfSuperAdmins; i++) {
                allDetails[i] = superAdminHashmap[superAdminsAccountDetails[i]];
            }
            return allDetails;
        } else {
            superAdmin[] memory allDetails = new superAdmin[](0);
            return allDetails;
        }
    }

    //add super admin credentials into table by hashing proper credentials
    function addSuperAdmin(superAdminDetails memory adminDetails, string memory adminHashCode) private{
        
        if (isSuperAdminUsernameTaken(adminHashCode)) {
            bytes32 usernameHash = getStringHashedToBytes32(adminDetails.encUsername);
            bytes32 passwordHash = getStringHashedToBytes32(adminDetails.password);
            
            superAdmin memory admin = superAdmin(adminDetails.name, adminDetails.emailId, adminDetails.username, usernameHash, passwordHash, true, true);

            superAdminHashmap[usernameHash] = admin;
            superAdminsAccountDetails[numberOfSuperAdmins] = usernameHash;

            numberOfSuperAdmins += 1;
        }
    }

    function storeSuperAdminAtPosition(superAdmin memory adminData, string memory encUsername) private {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);

        superAdminHashmap[usernameHash] = adminData;
    }

    //checks the hashmap, wheather admin details is present already
    function isSuperAdminPresent(superAdmin memory adminDetails, string memory encUsername) private view returns(bool) {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);

        superAdmin storage admin = superAdminHashmap[usernameHash];

        if (isEqual(admin.name, adminDetails.name) && isEqual(admin.emailId, adminDetails.emailId) && isEqual(admin.username, adminDetails.username) && isEqualByBytes32(admin.encUsername, adminDetails.encUsername)) {
            return true;
        }

        return false;
    }

    //checks if the admin username is already taken
    function isSuperAdminUsernameTaken(string memory encUsername) public view returns(bool) {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);

        superAdmin storage admin = superAdminHashmap[usernameHash];

        if (!admin.occupied) {
            return false;
        }

        return true;
    }

    //will add the details into hashmap once all the api calls are satisfied
    function finallyAddSuperAdmin(string memory name, string memory emailId, string memory username, string memory encUsername, string memory password, string memory adminUsername) public {
        superAdminDetails memory adminDetails = superAdminDetails(name, emailId, username, encUsername, password);
        if (isSuperAdminUsernameTaken(adminUsername)) {
            addSuperAdmin(adminDetails, adminUsername);
        }
    }

    //returns data by checking the hashmap if the admin is created
    function isSuperAdminAdded(string memory name, string memory emailId, string memory username, string memory encUsername, string memory password) public view returns(int) {
        
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);
        bytes32 passwordHash = getStringHashedToBytes32(password);

        superAdmin memory adminDetails = superAdmin(name, emailId, username, usernameHash, passwordHash, true, true);

        bool isPresent = isSuperAdminPresent(adminDetails, encUsername);

        if (isPresent) {
            return 200;
        }
        return 100;
    }

    function authSuperAdmin(string memory username, string memory encUsername, string memory password) public view returns(bool) {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);
        bytes32 passwordHash = getStringHashedToBytes32(password);
        
        superAdmin memory authAdmin = superAdminHashmap[usernameHash];
        bytes32 baseUsernameHash = getStringHashedToBytes32(authAdmin.username);
        bytes32 recievedUsernameHash = getStringHashedToBytes32(username);
        if (baseUsernameHash == recievedUsernameHash && authAdmin.encUsername == usernameHash && authAdmin.password == passwordHash) {
            return true;
        }
        return false;
    }

    //edit super admin details as a whole, which includes Name, Email id, Password
    function editSuperAdminAllDetails(string memory name, string memory emailId, string memory encUsername, string memory password) public {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);
        bytes32 passwordHash = getStringHashedToBytes32(password);
        sAdmin = superAdminHashmap[usernameHash];
        sAdmin.name = name;
        sAdmin.emailId = emailId;
        sAdmin.password = passwordHash;

        superAdminHashmap[usernameHash] = sAdmin;
    }

    //edit only Super Admin name
    function editSuperAdminName(string memory name, string memory encUsername) public {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);

        sAdmin = superAdminHashmap[usernameHash];
        sAdmin.name = name;

        storeSuperAdminAtPosition(sAdmin, encUsername);
    }

    //edit only Super Admin Email Id
    function editSuperAdminEmailId(string memory emailId, string memory encUsername) public {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);

        sAdmin = superAdminHashmap[usernameHash];
        sAdmin.emailId = emailId;

        storeSuperAdminAtPosition(sAdmin, encUsername);
    }

    //edit only Super Admin Password
    function editSuperAdminPassword(string memory password, string memory encUsername) public {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);
        bytes32 passwordHash = getStringHashedToBytes32(password);

        sAdmin = superAdminHashmap[usernameHash];
        sAdmin.password = passwordHash;

        storeSuperAdminAtPosition(sAdmin, encUsername);
    }

    //function to get the admin details
    function getSuperAdminDetails(string memory encUsername) public view returns(superAdmin memory) {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);
        return superAdminHashmap[usernameHash];
    }

    //function to create Default Super Admin
    function defaultSuperAdmin(string memory name, string memory emailId, string memory username, string memory encUsername, string memory password) public {
        if (!isDefaultAdminAdded) {
            bytes32 usernameHash = getStringHashedToBytes32(encUsername);
            bytes32 passwordHash = getStringHashedToBytes32(password);
            
            superAdmin memory admin = superAdmin(name, emailId, username, usernameHash, passwordHash, true, false);

            superAdminHashmap[usernameHash] = admin;
            isDefaultAdminAdded = true;
        }
    }

    function modifySuperAdminLoginLog(string memory encUsername, string memory dateTime) public {
        bytes32 encUsernameHash = getStringHashedToBytes32(encUsername);
        superAdminLoginLog[encUsernameHash] = dateTime;
    }

    function getSuperAdminLoginLog(string memory encUsername) public view returns(string memory) {
        bytes32 encUsernameHash = getStringHashedToBytes32(encUsername);
        return superAdminLoginLog[encUsernameHash];
    }

    //delete the super admin
    //the admin to be deleted and the admin deleting the super admin cannot be the same. The admin
    function deleteSuperAdmin(string memory username, string memory encUsername, string memory superAdminUsername, string memory superAdminEncUsername) public view returns(uint) {
        bytes32 superAdminEncUsernameHash = getStringHashedToBytes32(superAdminEncUsername);
        
        return 0;
    }

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    //---------------------------------------------------- Election Details ------------------------------------------------------------------------------------------------------------

    struct electionDetails {
        string electionAlias;
        string year;
        string date;
        uint numberOfConstituency;
        string typeOfConstituency;
        uint index;
        //hash value to store constituency details
        mapping(uint => constituencyDetails) cDetails;
    }

    struct constituencyDetails {
        string district;
        string state;
        string constituencyNumber;
        uint numberOfVoters;
        string dateOfElection;
        string openTime;
        string closeTime;
        //hash value to store voter's details
    }

    struct constituencyData {
        string district;
        string state;
        string constituencyNumber;
        uint numberOfVoters;
        string dateOfElection;
        string openTime;
        string closeTime;
    }

    struct electionData {
        string electionAlias;
        string year;
        string date;
        uint numberOfConsituency;
        string typeOfConstituency;
        uint indexSize;
    }

    struct superAdminForElection {
        uint index;
        mapping (uint => electionDetails) eDetails;
    }

    mapping (bytes32 => superAdminForElection) adminForElection;

    function createElectionUsingSuperAdmin(string memory username, string memory encUsername, string memory password, string memory electionAlias, string memory year, string memory date, uint numberOfConstituency, string memory typeOfConstituency) public {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 adminHashValue = getStringHashedToBytes32(encUsername);
            
            superAdminForElection storage adminElection = adminForElection[adminHashValue];
            uint electionIndex = adminElection.index;
            electionDetails storage eDetails = adminElection.eDetails[electionIndex];
            eDetails.electionAlias = electionAlias;
            eDetails.year = year;
            eDetails.date = date;
            eDetails.numberOfConstituency = numberOfConstituency;
            eDetails.typeOfConstituency = typeOfConstituency;

            adminElection.index += 1;
        }
    }

    function createConstituencyUsingSuperAdmin(string memory username, string memory encUsername, string memory password, uint eIndex, string memory district, string memory state, string memory constituencyNumber, uint numberOfVoters, string memory dateOfElection, string memory openTime, string memory closeTime) public {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 adminHashValue = getStringHashedToBytes32(encUsername);

            superAdminForElection storage adminElection = adminForElection[adminHashValue];
            electionDetails storage eDetails = adminElection.eDetails[eIndex];
            uint cIndex = eDetails.index;
            constituencyDetails storage cDetails = eDetails.cDetails[cIndex];
            cDetails.district = district;
            cDetails.state = state;
            cDetails.constituencyNumber = constituencyNumber;
            cDetails.numberOfVoters = numberOfVoters;
            cDetails.dateOfElection = dateOfElection;
            cDetails.openTime = openTime;
            cDetails.closeTime = closeTime;
        }
    }

    function getAllElectionData(string memory username, string memory encUsername, string memory password) public view returns(electionData[] memory) {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 usernameHash = getStringHashedToBytes32(encUsername);

            superAdminForElection storage adminElection = adminForElection[usernameHash];
            uint eCount = adminElection.index;
            electionData[] memory eData = new electionData[](eCount);
            for (uint i = 0; i < eCount; i++) {
                electionDetails storage eDetails = adminElection.eDetails[i];
                string memory electionAlias = eDetails.electionAlias;
                string memory year = eDetails.year;
                string memory date = eDetails.date;
                uint numberOfConstituency = eDetails.numberOfConstituency;
                string memory typeOfElection = eDetails.typeOfConstituency;
                uint eIndexCount = eDetails.index;
                electionData memory elData = electionData(electionAlias, year, date, numberOfConstituency, typeOfElection, eIndexCount);
                eData[i] = elData;
            }
            return eData;
        }
    }

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    function getStringHashedToBytes32(string memory toBeHashedString) private pure returns(bytes32) {
        return sha256(abi.encodePacked(toBeHashedString));
    }

    function isEqual(string memory input1, string memory input2) private pure returns(bool) {
        return (getStringHashedToBytes32(input1) == getStringHashedToBytes32(input2));
    }

    function isEqualByBytes32(bytes32 input1, bytes32 input2) private pure returns(bool) {
        return (input1 == input2);
    }

}