// SPDX-License-Identifier: MIT
pragma solidity >=0.5.16;

contract Storage {

    struct data {
        bool isdata;
    }

    mapping(uint256 => data) hmap;

    function store(uint256 position, bool flag) public returns(bool) {
        hmap[position].isdata = flag;
        return true;
    }
    
    function retrieve(uint256 position) public view returns(bool) {
        return hmap[position].isdata;
    }
}