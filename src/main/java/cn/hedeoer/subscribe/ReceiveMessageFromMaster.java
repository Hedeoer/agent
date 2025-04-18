package cn.hedeoer.subscribe;

import cn.hedeoer.util.RedisUtil;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.StreamEntryID;
import redis.clients.jedis.params.XAddParams;
import redis.clients.jedis.params.XReadParams;
import redis.clients.jedis.resps.StreamEntry;


import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ReceiveMessageFromMaster {
    /*
      0. 制定master和agent的 redis stream 通信的数据格式（即stream key的的内容格式） 参考 https://maxwells-daemon.io/dataformat/#insert
    * 1. 订阅master redis的某个topic
    * 2. 消费数据
    *
    * */

    public static void main(String[] args) {

        Jedis jedis = RedisUtil.getJedis();


      /*  StreamEntryID res1 = jedis.xadd("race:france",new HashMap<String,String>(){{put("rider","Castilla");put("speed","30.2");put("position","1");put("location_id","1");}} , XAddParams.xAddParams());

        System.out.println(res1); // >>> 1701760582225-0

        StreamEntryID res2 = jedis.xadd("race:france",new HashMap<String,String>(){{put("rider","Norem");put("speed","28.8");put("position","3");put("location_id","1");}} , XAddParams.xAddParams());

        System.out.println(res2); // >>> 1701760582225-1

        StreamEntryID res3 = jedis.xadd("race:france",new HashMap<String,String>(){{put("rider","Prickett");put("speed","29.7");put("position","2");put("location_id","1");}} , XAddParams.xAddParams());

        System.out.println(res3); // >>> 1701760582226-0*/


//        List<StreamEntry> res4 = jedis.xrange("race:france","1744008233910-00","+",3);
//
//        System.out.println(res4); // >>> [1701760841292-0 {rider=Castilla, speed=30.2, location_id=1, position=1}, 1701760841292-1 {r

        // xread

        List<Map.Entry<String, List<StreamEntry>>> res18= jedis.xread(XReadParams.xReadParams().count(2),new HashMap<String,StreamEntryID>(){{put("race:france",new StreamEntryID());}});
        System.out.println(
                res18
        );
    }



}
