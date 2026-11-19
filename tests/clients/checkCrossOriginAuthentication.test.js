const chai = require('chai');
const expect = chai.expect;
const checkCrossOriginAuthentication = require('../../analyzer/lib/clients/checkCrossOriginAuthentication');
const CONSTANTS = require("../../analyzer/lib/constants");

describe('checkCrossOriginAuthentication', function() {

  it('should return an empty report when clients array is empty', async function () {
    const options = {
      clients: []
    };

    const { details: report } = await checkCrossOriginAuthentication(options);
    expect(report).to.be.an('array').that.is.empty;
  });

  it('should return a report when cross_origin_authentication is enabled', async function () {
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

    const { details: report } = await checkCrossOriginAuthentication(options);
    expect(report).to.have.lengthOf(1);
    expect(report[0].name).to.equal('Client 1 (client_id_1)');
    expect(report[0].report).to.have.lengthOf(1);
    expect(report[0].report[0]).to.include({
      name: 'Client 1 (client_id_1)',
      client_id: 'client_id_1',
      field: 'cross_origin_authentication_enabled',
      status: CONSTANTS.FAIL,
      app_type: 'spa'
    });
  });

  it('should return a success report when cross_origin_authentication is disabled', async function () {
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

    const { details: report } = await checkCrossOriginAuthentication(options);
    expect(report).to.have.lengthOf(1);
    expect(report[0].report).to.have.lengthOf(1);
    expect(report[0].report[0]).to.include({
      client_id: 'client_id_2',
      field: 'cross_origin_authentication_disabled',
      status: CONSTANTS.SUCCESS
    });
  });

  it('should handle cases where client_id is missing', async function () {
    const options = {
      clients: [
        {
          name: 'Client 3',
          cross_origin_authentication: true,
          app_type: 'spa',
        }
      ]
    };

    const { details: report } = await checkCrossOriginAuthentication(options);
    expect(report).to.have.lengthOf(1);
    expect(report[0].report).to.have.lengthOf(1);
    expect(report[0].report[0]).to.include({
      name: 'Client 3',
      client_id: 'Client 3',
      field: 'cross_origin_authentication_enabled',
      status: CONSTANTS.FAIL,
      app_type: 'spa'
    });
  });

  it('should return a success report if cross_origin_authentication is false and other properties exist', async function () {
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

    const { details: report } = await checkCrossOriginAuthentication(options);
    expect(report).to.have.lengthOf(1);
    expect(report[0].report).to.have.lengthOf(1);
    expect(report[0].report[0]).to.include({
      client_id: 'client_id_4',
      field: 'cross_origin_authentication_disabled',
      status: CONSTANTS.SUCCESS
    });
  });
});
