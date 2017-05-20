/// <reference path="../typings/globals/node/index.d.ts" />
/// <reference path="../typings/modules/bluebird/index.d.ts" />
/// <reference path="./dns.d.ts" />
import * as dns from 'dns'
import * as event from 'events'
import * as fs from 'fs'
import * as dgram from 'dgram'
import * as packet from 'dns-packet'
import * as pcap from 'pcap'
import { StringDecoder } from 'string_decoder'

import pullutionIpList from './pollution'

interface UnoDnsConfig {
  pullutionIpList?: string[]
  dnsList?: string[]
  port?: number
}

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
  address: string
  family: string
  port: number
}

interface dnsCacheList {
  [address: string] : Buffer
}

class Dns {
  private server: dgram.Socket
  private dnsCache: dnsCacheList
  private dict: AddressInfo[]
  private pullutionIpList: string[]
  private dnsList: string[]
  private port: number
  

  constructor (config: UnoDnsConfig) {
    this.pullutionIpList = config.pullutionIpList || pullutionIpList
    this.dnsList = config.dnsList || ['8.8.8.8']
    this.port = config.port

    this.dict = []
    this.dnsCache = {}

    this.setDnsServer(this.dnsList)
    this.server = dgram.createSocket('udp4')

    this.server.on('listening', this.onlisten.bind(this))
    this.server.on('message', this.onmessage.bind(this))
    this.server.on('error', this.onerror.bind(this))
  }

  /**
   * 设置 DNS 缓存
   * @param address 
   * @param answers 
   */
  public setCache (address: string, message: Buffer) {
    this.dnsCache[address] = message
  }

  /**
   * 修改 DNS 列表
   * @param dnsList DNS 列表
   */
  public setDnsServer (dnsList: string[]) {
    this.dnsList = dnsList
    dns.setServers(dnsList)
  }

  /**
   * 启动监听
   * @param port 端口
   */
  public listen (port?: number) {
    this.port = port || this.port
    this.server.bind(this.port)
  }

  /**
   * listening 事件触发处理
   */
  private onlisten () {
    const address = this.server.address()
    console.log(`server listening ${address.address}:${address.port}`)
  }

  /**
   * message 事件触发处理
   * TODO: 不解析 Buffer
   * @param message 
   * @param rinfo 
   */
  private onmessage (message: Buffer, rinfo: dgram.AddressInfo) {
    const data: Packet = packet.decode(message)
    if (data.type === 'query') {
      if (this.dnsCache[data.questions[0].name]) {
        if (data.questions.length > 1) {
          console.log(data.questions)
        }
        const message = packet.decode(this.dnsCache[data.questions[0].name])
        message.id = data.id
        message.questions = data.questions
        console.log('使用缓存')
        this.server.send(packet.encode(message), 0, packet.encodingLength(message), rinfo.port, rinfo.address)
      } else {
        this.dict[data.id] = rinfo
        // data.questions.forEach(question => question.name = this.confuseAddress(question.name))
        this.server.send(packet.encode(data), 0, packet.encodingLength(data), 53, this.dnsList[0])
      }
    } else {
      if (!this.isPolluted(data.answers)) {
        const origin = this.dict[data.id]
        this.setCache(data.questions[0].name, message)
        this.server.send(message, 0, message.length, origin.port, origin.address)
        // if (Math.random() < 0.1) console.log(data)
      } else {
        console.log('拒绝投毒')
      }
    }
  }

  private onerror (err: Error) {
    console.log(err)
  }

  private isPolluted (answers) {
    for (const answer of answers) {
      if (this.pullutionIpList.includes(answer.data)) {
        return true
      }
    }
    return false
  }

  /**
   * 域名混淆处理
   */
  private confuseAddress (address: string) : string {
    return address.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('')
  }

  /**
   * 测试
   */
  public ping () {
    const buf = packet.encode({
      type: 'query',
      id: 1,
      flags: packet.RECURSION_DESIRED,
      questions: [{
        type: 'A',
        name: 'www.google.com'
      }]
    })
    this.server.send(buf, 0, buf.length, this.port, '127.0.0.1')
  }

}

const test = new Dns({
  port: 53
})
test.listen()
// test.ping()