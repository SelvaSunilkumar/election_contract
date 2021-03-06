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

    //store super admin details based on the hash value of encryptedUserName hash value
    mapping(bytes32 => superAdmin) private superAdminHashmap;
    mapping (uint=> bytes32) private superAdminsAccountDetails;
    mapping(bytes32 => string) private superAdminLoginLog;

    //get all details of Super admins
    /*function getAllSuperAdminDetails(string memory encUsername) public view returns(superAdmin[] memory) {

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
    }*/

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

    /*function storeSuperAdminAtPosition(superAdmin memory adminData, string memory encUsername) private {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);

        superAdminHashmap[usernameHash] = adminData;
    }*/

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

    function authSuperAdminEnc(string memory username) public view returns(bool) {
        bytes32 usernameHash = getStringHashedToBytes32(username);

        superAdmin memory authAdmin = superAdminHashmap[usernameHash];
        if (authAdmin.encUsername == usernameHash) {
            return true;
        }
        return false;
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
    /*function editSuperAdminAllDetails(string memory name, string memory emailId, string memory encUsername, string memory password) public {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);
        bytes32 passwordHash = getStringHashedToBytes32(password);
        superAdmin memory sAdmin = superAdminHashmap[usernameHash];
        sAdmin.name = name;
        sAdmin.emailId = emailId;
        sAdmin.password = passwordHash;

        superAdminHashmap[usernameHash] = sAdmin;
    }

    //edit only Super Admin name
    function editSuperAdminName(string memory name, string memory encUsername) public {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);

        superAdmin memory sAdmin = superAdminHashmap[usernameHash];
        sAdmin.name = name;

        storeSuperAdminAtPosition(sAdmin, encUsername);
    }

    //edit only Super Admin Email Id
    function editSuperAdminEmailId(string memory emailId, string memory encUsername) public {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);

        superAdmin memory sAdmin = superAdminHashmap[usernameHash];
        sAdmin.emailId = emailId;

        storeSuperAdminAtPosition(sAdmin, encUsername);
    }

    //edit only Super Admin Password
    function editSuperAdminPassword(string memory password, string memory encUsername) public {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);
        bytes32 passwordHash = getStringHashedToBytes32(password);

        superAdmin memory sAdmin = superAdminHashmap[usernameHash];
        sAdmin.password = passwordHash;

        storeSuperAdminAtPosition(sAdmin, encUsername);
    }

    //function to get the admin details
    function getSuperAdminDetails(string memory encUsername) public view returns(superAdmin memory) {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);
        return superAdminHashmap[usernameHash];
    }*/

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

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    //---------------------------------------------------- Election Details ------------------------------------------------------------------------------------------------------------

    /*struct electionDetails {
        string electionId;
        string electionAlias;
        string year;
        string date;
        uint numberOfConstituency;
        string typeOfConstituency;
        uint index;
        bool flag;
        //hash value to store constituency details
        mapping(uint => bytes32) constituencyStorageHash;
    }

    struct constituencyDetails {
        string district;
        string state;
        string constituencyNumber;
        uint numberOfVoters;
        string dateOfElection;
        string time;
        bool flag;
        //hash value to store voter's details
    }

    struct constituencyData {
        string district;
        string state;
        string constituencyNumber;
        uint numberOfVoters;
        string dateOfElection;
        string time;
    }

    struct electionData {
        string electionAlias;
        string year;
        string date;
        uint numberOfConsituency;
        string typeOfConstituency;
        uint indexSize;
        uint index;
    }

    struct superAdminForElection {
        uint index;
        mapping (uint => bytes32) electionStorageHash;
    }

    mapping (bytes32 => superAdminForElection) adminForElection;
    mapping (bytes32 => electionDetails) electionMap;
    mapping (bytes32 => constituencyDetails) constituencyMap;

    function createConstituencyUsingSuperAdmin(string memory username, string memory encUsername, string memory password, uint userElectionIndex, string memory constituencyId, string memory district, string memory stateName,string memory constituencyNumber, uint numberOfVoters, string memory date, string memory time) public {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 adminHash = getStringHashedToBytes32(encUsername);
            bytes32 constituencyIndexHash = getStringHashedToBytes32(constituencyId);

            superAdminForElection storage adminElection = adminForElection[adminHash];

            bytes32 electionAddress = adminElection.electionStorageHash[userElectionIndex];
            electionDetails storage eDetails = electionMap[electionAddress];

            uint cIndex = eDetails.index;
            constituencyDetails storage cDetails = constituencyMap[constituencyIndexHash];
            cDetails.district = district;
            cDetails.state = stateName;
            cDetails.constituencyNumber = constituencyNumber;
            cDetails.numberOfVoters = numberOfVoters;
            cDetails.dateOfElection = date;
            cDetails.time = time;
            cDetails.flag = true;

            eDetails.constituencyStorageHash[cIndex] = constituencyIndexHash;
            eDetails.index += 1;
        }
    }

    function createElectionUsingSuperAdmin(string memory username, string memory encUsername, string memory password, string memory electionId ,string memory electionAlias, string memory year, string memory typeOfElection, string memory date, uint numberOfConstituencyT) public {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 adminHashValue = getStringHashedToBytes32(encUsername);
            bytes32 electionIdHashValue = getStringHashedToBytes32(electionId);
            
            electionDetails storage eDetails = electionMap[electionIdHashValue];
            eDetails.electionId = electionId;
            eDetails.electionAlias = electionAlias;
            eDetails.year = year;
            eDetails.date = date;
            eDetails.typeOfConstituency = typeOfElection;
            eDetails.numberOfConstituency = numberOfConstituencyT;
            eDetails.flag = true;

            superAdminForElection storage adminElection = adminForElection[adminHashValue];
            uint electionIndex = adminElection.index;
            adminElection.electionStorageHash[electionIndex] = electionIdHashValue;
            adminElection.index += 1;
        }
    }

    /*function createConstituencyUsingSuperAdmin(string memory username, string memory encUsername, string memory password, string memory electionId, string memory constituencyId,string memory district, string memory state, string memory constituencyNumber, uint numberOfVoters, string memory date, string memory time) public {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 electionIndexHash = getStringHashedToBytes32(electionId);
            bytes32 constituencyIndexHash = getStringHashedToBytes32(constituencyId);

            electionDetails storage eDetails = electionMap[electionIndexHash];
            uint cIndex = eDetails.index;
            constituencyDetails storage cDetails = constituencyMap[constituencyIndexHash];
            cDetails.district = district;
            cDetails.state = state;
            cDetails.constituencyNumber = constituencyNumber;
            cDetails.numberOfVoters = numberOfVoters;
            cDetails.dateOfElection = date;
            cDetails.time = time;
            cDetails.flag = true;

            eDetails.constituencyStorageHash[cIndex] = constituencyIndexHash;
            eDetails.index += 1;
        }
    }*/

    /*function getAllElectionData(string memory username, string memory encUsername, string memory password) public view returns(electionData[] memory) {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 usernameHash = getStringHashedToBytes32(encUsername);

            superAdminForElection storage adminElection = adminForElection[usernameHash];
            uint adminIndex = adminElection.index;
            electionData[] memory eData = new electionData[](adminIndex);

            for (uint i = 0; i < adminIndex; i++) {
                bytes32 electionAddress = adminElection.electionStorageHash[i];
                electionDetails storage eDetails = electionMap[electionAddress];
                string memory electionAlias = eDetails.electionAlias;
                string memory year = eDetails.year;
                string memory date = eDetails.date;
                uint numberOfConsituency = eDetails.numberOfConstituency;
                string memory typeOfConstituency = eDetails.typeOfConstituency;
                uint size = eDetails.index;

                electionData memory data = electionData(electionAlias, year, date, numberOfConsituency, typeOfConstituency, size, i);
                eData[i] = data;
            }
            return eData;
        } else {
            electionData[] memory eData = new electionData[](0);
            return eData;
        }
    }

    function getConstituentDetails(string memory username, string memory encUsername, string memory password, uint electionIndex) public view returns(constituencyData[] memory) {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 adminHashValue = getStringHashedToBytes32(encUsername);
            
            superAdminForElection storage adminElection = adminForElection[adminHashValue];
            bytes32 electionAddress = adminElection.electionStorageHash[electionIndex];

            electionDetails storage eDetails = electionMap[electionAddress];
            uint size = eDetails.index;

            constituencyData[] memory cData = new constituencyData[](size);

            for (uint i = 0; i < size; i++) {
                bytes32 constituencyAddress = eDetails.constituencyStorageHash[i];
                constituencyDetails storage cDetails = constituencyMap[constituencyAddress];

                string memory district = cDetails.district;
                string memory stateName = cDetails.state;
                string memory constituencyNumber = cDetails.constituencyNumber;
                uint numberOfVoters = cDetails.numberOfVoters;
                string memory dateOfElection = cDetails.dateOfElection;
                string memory time = cDetails.time;

                constituencyData memory data = constituencyData(district, stateName, constituencyNumber, numberOfVoters, dateOfElection, time);
                cData[i] = data;
            }

            return cData;
        } else {
            constituencyData[] memory cData = new constituencyData[](0);
            return cData;
        }
    }

    function isElectionProvidedUnderAdmin(string memory encUsername, string memory electionId, uint electionIndex) private view returns(bool) {
        bytes32 usernameHash = getStringHashedToBytes32(encUsername);

        superAdminForElection storage adminElection = adminForElection[usernameHash];
        bytes32 electionDataAddress = adminElection.electionStorageHash[electionIndex];

        electionDetails storage adminElectionDetails = electionMap[electionDataAddress];
        string memory adminElectionId = adminElectionDetails.electionId;

        if (isEqual(adminElectionId, electionId)) {
            return true;
        }
        return false;
    }*/

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    struct stateDetails {
        string constitutionId;
        string state;
        string district;
        string constitutionName;
        string taluk;
        bool occupied;
    }

    struct stateInfo {
        string stateName;
        uint index;
    }

    struct state {
        bool occupied;
        string stateName;
        uint statesCount;
        mapping (uint => string) details;
    }

    uint numberOfStates = 0;
    uint numberOfConstituency = 0;

    mapping (uint => string) stateLocationHash;
    mapping (string => state) stateList;
    mapping (string => stateDetails) constituencyTable;

    function addConstituencyData(string memory username, string memory encUsername, string memory password, string memory stateId, string memory stateName, string memory constituencyId, string memory district, string memory constitutionName, string memory taluk) public {
        if (authSuperAdmin(username, encUsername, password) && !constituencyTable[constituencyId].occupied) {
            state storage stateData = stateList[stateId];
            if (!stateData.occupied) {
                stateLocationHash[numberOfStates] = stateId;
                stateData.occupied = true;
                numberOfStates += 1;
            }
            stateData.stateName = stateName;
            uint index = stateData.statesCount;
            stateDetails memory details = stateDetails(constituencyId, stateName, district, constitutionName, taluk, true);
            stateData.details[index] = constituencyId;
            constituencyTable[constituencyId] = details;
            stateData.statesCount += 1;
            numberOfConstituency += 1;
        }
    }

    function isConstituencyIdOccupied(string memory username, string memory encUsername, string memory password, string memory constituencyId) public view returns(bool) {
        if (authSuperAdmin(username, encUsername, password)) {
            stateDetails memory details = constituencyTable[constituencyId];
            return details.occupied;
        } else {
            return false;
        }
    }

    function getStateList(string memory username, string memory encUsername, string memory password) public view returns(stateInfo[] memory) {
        if (authSuperAdmin(username, encUsername, password)) {
            stateInfo[] memory stateArray = new stateInfo[](numberOfStates);
            for (uint i = 0; i < numberOfStates; i++) {
                string memory stateLocationAddress = stateLocationHash[i];
                state storage stateData = stateList[stateLocationAddress];
                stateArray[i].stateName = stateData.stateName;
                stateArray[i].index = i;
            }
            return stateArray;
        } else {
            stateInfo[] memory data = new stateInfo[](0);
            return data;
        }
    }

    function getCorresspondingStateList(string memory username, string memory encUsername, string memory password, uint index) public view returns(stateDetails[] memory) {
        if (authSuperAdmin(username, encUsername, password)) {
            string memory stateAddress = stateLocationHash[index];
            state storage stateData = stateList[stateAddress];
            uint size = stateData.statesCount;
            stateDetails[] memory stateArray = new stateDetails[](size);
            for (uint i = 0; i < size; i++) {
                string memory id = stateData.details[i];
                stateArray[i] = constituencyTable[id];
            }
            return stateArray;
        } else {
            stateDetails[] memory data = new stateDetails[](0);
            return data;
        }
    }

    function getCorrespondingConstituencyDetail(string memory username, string memory encUsername, string memory password, string memory constituencyId) public view returns(stateDetails memory) {
        if (authSuperAdmin(username, encUsername, password)) {
            return constituencyTable[constituencyId];
        }
        revert("Not Found");
    }

    function getCorrespondingConstituencyDetails(string memory constituencyId) public view returns(stateDetails memory) {
        return constituencyTable[constituencyId];
    }

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    
    struct voter {
        string aadharNumber;
        string voterId;
        string name;
        string dateOfBirth;
        string constituencyId;
        string contactNumber;
        string emailAddress;
        string residentialAddress;
        bool occupied;
    }

    struct individualVoterData {
        string aadharNumber;
        string voterId;
        string name;
        string dateOfBirth;
        string state;
        string district;
        string taluk;
        string constituencyId;
        string residentialAddress;
    }

    struct constituencyVoters {
        uint numberOfVoters;
        mapping (uint => string) voter;
    }

    mapping(string => constituencyVoters) votersList;
    mapping(string => voter) votersTable;

    function addVoterDetails(string memory encUsername, string memory aadharNumber, string memory voterId, string memory name, string memory dateOfBirth, string memory constituencyId, string memory contactNumber, string memory emailAddress, string memory residentialAddress) public {
        if (authSuperAdminEnc(encUsername)) {
            voter memory voterData = voter(aadharNumber, voterId, name, dateOfBirth, constituencyId, contactNumber, emailAddress, residentialAddress, true);
            votersTable[voterId] = voterData;
            constituencyVoters storage list = votersList[constituencyId];
            uint size = list.numberOfVoters;
            list.voter[size] = voterId;
            list.numberOfVoters += 1;
        }
    }

    function getIndividualVoterDetail(string memory username, string memory encUsername, string memory password, string memory voterId) public view returns(individualVoterData memory) {
        if (authSuperAdmin(username, encUsername, password) && votersTable[voterId].occupied) {
            voter memory voterData = votersTable[voterId];
            string memory aadharNumber = voterData.aadharNumber;
            string memory name = voterData.name;
            string memory dateOfBirth = voterData.dateOfBirth;
            
            string memory constituencyId = voterData.constituencyId;
            stateDetails memory stateData = constituencyTable[constituencyId];

            string memory stateName = stateData.state;
            string memory district = stateData.district;
            string memory taluk = stateData.taluk;
            string memory residentialAddress = voterData.residentialAddress;

            individualVoterData memory data = individualVoterData(aadharNumber, voterId, name, dateOfBirth, stateName, district, taluk, constituencyId, residentialAddress);
            return data;
        }
        revert("Not found");
    }

    function getConstituencyVotersList(string memory username, string memory encUsername, string memory password, string memory constituencyId) public view returns(voter[] memory) {
        if (authSuperAdmin(username, encUsername, password)) {
            constituencyVoters storage list = votersList[constituencyId];
            uint size = list.numberOfVoters;

            voter[] memory voters = new voter[](size);

            for (uint i = 0; i < size; i++) {
                string memory voterId = list.voter[i];
                voter memory details = votersTable[voterId]; 
                voters[i] = details;
            }
            return voters;
        }
        revert();
    }

    function isVoterIdValid(string memory username, string memory encUsername, string memory password, string memory voterId) public view returns(uint) {
        if (authSuperAdmin(username, encUsername, password)) {
            if (votersTable[voterId].occupied) {
                return 500; //voter Id taken (Not available)
            }
            return 200; //available
        } else {
            return 400; //invalid user
        }
    }

    //----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

    struct election {
        string electionAlias;
        string electionId;
        string year;
        string dateOfElection;
        bool occupied;
        uint numberOfConstituency;
        mapping (uint => string) constituencyAddress;
    }

    struct electionDetail {
        string electionAlias;
        string electionId;
        string year;
        string dateOfElection;
        uint numberOfConstituency;
    }

    struct adminAssociatedElection {
        uint numberOfElection;
        mapping (uint => string) electionId;
    }

    struct constituencyElection {
        uint numberOfElection;
        mapping (uint => string) electionList;
    }

    mapping (string => election) electionTable;
    mapping (bytes32 => adminAssociatedElection) adminElection;
    mapping (string => constituencyElection) electionConstituencyTable;

    function createElection(string memory username, string memory encUsername, string memory password, string memory electionAlias, string memory electionId, string memory year, string memory dateOfElection) public {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 usernameHash = getStringHashedToBytes32(encUsername);

            adminAssociatedElection storage associatedElection = adminElection[usernameHash];
            uint electionCount = associatedElection.numberOfElection;
            associatedElection.electionId[electionCount] = electionId;
            associatedElection.numberOfElection += 1;

            election storage electionData = electionTable[electionId];
            electionData.electionAlias = electionAlias;
            electionData.electionId = electionId;
            electionData.year = year;
            electionData.dateOfElection = dateOfElection;
            electionData.occupied = true;
        }
    }

    function getElection(string memory username, string memory encUsername, string memory password) public view returns(electionDetail[] memory) {
        if (authSuperAdmin(username, encUsername, password)) {
            bytes32 usernameHash = getStringHashedToBytes32(encUsername);

            adminAssociatedElection storage associatedElection = adminElection[usernameHash];
            uint numberOfElections = associatedElection.numberOfElection;

            electionDetail[] memory detail = new electionDetail[](numberOfElections);
            for (uint index = 0; index < numberOfElections; index++) {
                string memory electionIndex = associatedElection.electionId[index];
                election storage electionData = electionTable[electionIndex];
                electionDetail memory eDetail = electionDetail(electionData.electionAlias, electionData.electionId, electionData.year, electionData.dateOfElection, electionData.numberOfConstituency);
                detail[index] = eDetail;
            }
            return detail;
        }
        revert("invalid authentication");
    }

    function addElectionConstitution(string memory username, string memory encUsername, string memory password, string memory electionId, string memory constituencyId) public {
        if (authSuperAdmin(username, encUsername, password)) {
            election storage electionData = electionTable[electionId];
            uint indexOfConstituency = electionData.numberOfConstituency;
            electionData.constituencyAddress[indexOfConstituency] = constituencyId;
            electionData.numberOfConstituency += 1;

            constituencyElection storage cElection = electionConstituencyTable[constituencyId];
            uint numberOfConstituencyElection = cElection.numberOfElection;
            cElection.electionList[numberOfConstituencyElection] = electionId;
            cElection.numberOfElection += 1;
        }
    }

    function getElectionConstituencyDetail(string memory username, string memory encUsername, string memory password, string memory electionId) public view returns(stateDetails[] memory) {
        if (authSuperAdmin(username, encUsername, password)) {
            election storage electionData = electionTable[electionId];
            uint count = electionData.numberOfConstituency;

            stateDetails[] memory details = new stateDetails[](count);

            for (uint index = 0; index < count; index++) {
                string memory consituencyAddress = electionData.constituencyAddress[index];
                details[index] = getCorrespondingConstituencyDetails(consituencyAddress);
            }
            return details;
        }
        revert("invalid authentication");
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