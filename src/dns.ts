/// <reference path="../typings/globals/node/index.d.ts" />
/// <reference path="../typings/modules/bluebird/index.d.ts" />
/// <reference path="./dns.d.ts" />
// 测试文件
// 测试文件
// 测试文件
// 测试文件

import * as dns from 'dns'
import * as event from 'events'
import * as fs from 'fs'
import * as dgram from 'dgram'
import * as packet from 'dns-packet'
import * as pcap from 'pcap'
import { StringDecoder } from 'string_decoder'

import pullutionIpList from './pollution'

interface Answer {
    name: string,
    type: string,
    class: number,
    ttl: number,
    flush: boolean,
    data: string
}
interface Packet {
  id: number
  type: string
  flags: number,
  questions: {
    name: string,
    type: string,
    class: number
  }[]
  answers: Answer[]
  authorities: {}[]
  additionals: {}[]
}

interface AddressInfo {
    address: string;
    family: string;
    port: number;
}

(async () => {

  dns.setServers(['8.8.8.8'])
  const pcap_session = pcap.createSession('', 'udp port 53 and src 8.8.8.8')
  const addresses = dns.getServers()
  const decoder = new StringDecoder('utf8')

  pcap_session.on('packet', function (raw_packet) {
     const packet = pcap.decode.packet(raw_packet)
     // TODO
     console.log('-----------')
     const result = decoder.write(packet.payload.payload.payload)
     console.log('-----------')
     const ip = result.match(/.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)[1]
     if (pullutionIpList.includes(ip)) {
      console.log('污染啦啦啦啦')
     }
  })

  const server = dgram.createSocket('udp4')
  const resolveServer = dgram.createSocket('udp4')

  const dict: AddressInfo[] = []

  server.on('error', err => {
    console.log(err)
  })

  const resolveAddress = function resolve(domain: string, rrtype: string, callback?: (err: Error, addresses: string[]) => void) : Promise<string[]> {
    return new Promise((resolve, reject) => {
      dns.resolve(domain, rrtype, (err, res) => {
        err ? reject(err) : resolve(res)
      })
    })
  }

  const confuseAddress = function (address: string) : string {
    return address.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('')
  }

  server.on('message', async (message, rinfo) => {
    const data: Packet = packet.decode(message)
    if (data.type === 'query') {
      dict[data.id] = rinfo
      data.questions.forEach(question => question.name = confuseAddress(question.name))
      server.send(packet.encode(data), 0, packet.encodingLength(data), 53, '8.8.8.8')
    } else {
      console.log(data.type)
    }

  })

  server.on('listening', () => {
    var address = server.address()
    console.log(`server listening ${address.address}:${address.port}`)
    server.send(buf, 0, buf.length, address.port, '127.0.0.1')
  })

  resolveServer.bind()
  // server.bind()
  server.bind(53)

  const buf = packet.encode({
    type: 'query',
    id: 1,
    flags: packet.RECURSION_DESIRED,
    questions: [{
      type: 'A',
      name: 'www.google.com'
    }]
  })


})()