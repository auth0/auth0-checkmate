const chai = require('chai');
const expect = chai.expect;
const checkCrossOriginAuthentication = require('../../analyzer/lib/clients/checkCrossOriginAuthentication');
const CONSTANTS = require("../../analyzer/lib/constants");

describe('checkCrossOriginAuthentication', function() {

  it('should return an empty report when clients array is empty', function() {
    const options = {
      clients: []
    };

    checkCrossOriginAuthentication(options, (report) => {
      expect(report).to.be.an('array').that.is.empty;
    });
  });

  it('should return a report when cross_origin_authentication is enabled', function() {
    const options = {
      clients: [
        {
          client_id: 'client_id_1',
          name: 'Client 1',
          cross_origin_authentication: true,
          app_type: 'spa',
        }
      ]
    };

    checkCrossOriginAuthentication(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0]).to.include({
        client_id: 'client_id_1',
        field: 'cross_origin_authentication_enabled',
        status: CONSTANTS.FAIL,
        app_type: 'spa'
      });
      expect(report[0].name).to.equal('Client 1 (client_id_1)');
    });
  });

  it('should not return a report when cross_origin_authentication is disabled', function() {
    const options = {
      clients: [
        {
          client_id: 'client_id_2',
          name: 'Client 2',
          cross_origin_authentication: false,
          app_type: 'spa',
        }
      ]
    };

    checkCrossOriginAuthentication(options, (report) => {
      expect(report).to.be.an('array').that.is.empty;
    });
  });

  it('should handle cases where client_id is missing', function() {
    const options = {
      clients: [
        {
          name: 'Client 3',
          cross_origin_authentication: true,
          app_type: 'spa',
        }
      ]
    };

    checkCrossOriginAuthentication(options, (report) => {
      expect(report).to.have.lengthOf(1);
      expect(report[0]).to.include({
        client_id: 'Client 3',
        field: 'cross_origin_authentication_enabled',
        status: CONSTANTS.FAIL,
        app_type: 'spa'
      });
      expect(report[0].name).to.equal('Client 3');
    });
  });

  it('should return an empty report if cross_origin_authentication is false and other properties exist', function() {
    const options = {
      clients: [
        {
          client_id: 'client_id_4',
          name: 'Client 4',
          cross_origin_authentication: false,
          app_type: 'spa',
          callbacks: ['http://localhost:3000'],
        }
      ]
    };

    checkCrossOriginAuthentication(options, (report) => {
      expect(report).to.be.an('array').that.is.empty;
    });
  });
});
