
#include <string>
#include <iostream>
#include <assert.h>
#include <stdint.h>

using namespace std;

class BasePBMsgHanle
{
    public:
	
#if 0
    void initHandles()
    {
        registerHandle(&BasePBMsgHanle::handleProtoPerson);
        registerHandle(&BasePBMsgHanle::handleProtoTest);
    }
#endif
    
    /*  处理网络消息
     *  data 为一个完整的数据包
     */
    void    handle(const char* data)
    {
        bool ret = false;
        
        const char * current=data;
        
        //在网络上传输的一个数据包总长度
        int packetLength=0;
        
        //从第一个位置上获取到数据包总长度
        memcpy(&packetLength, data, sizeof(int32_t));
        
        //指针后移
        current+=sizeof(int32_t);
        
        //Message名字的长度
        int protoNameLength=0;
        
        //从第二个位置上获取Message的名字的长度
        memcpy(&protoNameLength, current, sizeof(int32_t));
        
        //指针后移
        current+=sizeof(int32_t);
        
        //从第三个位置上获取Message的名字
        string name(current,protoNameLength);
        
        //指针后移
        current+=protoNameLength;
        
        //取得Message的字节数
        int messageSize=packetLength-(sizeof(int32_t)+sizeof(int32_t)+protoNameLength);
        
        do{
            
            msg_handle callback = m_callbacks[name];
            
            assert(callback != NULL);
            
            if(callback == NULL)
            {
                std::cout<<"proto "<<name<<" had not register handler"<<std::endl;
                break;
            }
            const ::google::protobuf::Descriptor* descriptor = m_descriptors[name];
            assert(descriptor != NULL);
            if(descriptor == NULL)
            {
                std::cout<<"proto "<<name<<" had no descriptor"<<std::endl;
                break;
            }
            const google::protobuf::Message* prototype = google::protobuf::MessageFactory::generated_factory()->GetPrototype(descriptor);
            assert(prototype != NULL);
            if(prototype == NULL)
            {
                std::cout<<"proto "<<name<<" had no prototype"<<std::endl;
                break;
            }
            google::protobuf::Message* msg = prototype->New();
            ret = msg->ParseFromArray(current,messageSize);
            if(ret)
            {
                (this->*callback)(msg);
            }
            else
            {
                std::cout<<"proto "<<name<<" parse fail"<<std::endl;
            }
         
        }while(0);
    }
private:
#if 0
    void handleProtoTest(test* test)
    {
        cout <<"test->price()="<< test->price() << endl;
        cout << "test->userid()="<<test->userid() << endl;
        cout << "test->time()="<<test->time() << endl;
    }
    void handleProtoPerson(person* person)
    {
        cout << "person->age()="<<person->age() << endl;
        cout << "person->userid()="<<person->userid() << endl;
        cout << "person->name()="<<person->name() << endl;
    }
#endif
    
private:
    
    typedef void (BasePBMsgHanle::*msg_handle)(::google::protobuf::Message*);
    
	/* all the sub class register to here */
    static map<string, msg_handle>                                 m_callbacks;
    
    static map<string, const ::google::protobuf::Descriptor*>      m_descriptors;

    template<typename MSGTYPE>
    void registerHandle(void (BasePBMsgHanle::*callback)(MSGTYPE*))
    {
        const ::google::protobuf::Descriptor*des =MSGTYPE::descriptor();
        assert(des != NULL);
        if(des != NULL)
        {
            m_callbacks[des->full_name()] = (msg_handle)callback;
            m_descriptors[des->full_name()] = des;
        }
    }

 
};

class BasePBMsgBuilder
{
    public:
    /*  发送proto msg到指定缓冲区
     *  int32_t   packetLength 数据包总长度
     *  int32_t   messageNameLength 消息名长度
     *  char[]    messageName 消息名
     *  char[]    Message 消息
     *  char*     buffer 缓冲区
     *  int       maxLength 消息的最大长度
     */
    template<typename MSGTYPE>
    static int sendMessageToBuffer(MSGTYPE& msg, char* buffer, int maxLength){
        
        char * current=buffer;
        
        //Message的字节数
        int messageSize=msg.ByteSize();
        
        //Message的名字
        string messageName=MSGTYPE::descriptor()->full_name();
        
        //Message名字的长度
        size_t messageNameLength=messageName.size();
        
        //消息组成 messageSize+messageNameLength+messageName+Message
        size_t packetLength=sizeof(int32_t)+sizeof(int32_t)+messageNameLength+messageSize;
        
        if (packetLength>maxLength) {
            return -1;
        }
        
        //将数据包总长度放在第一个位置
        memcpy(current, &packetLength, sizeof(int32_t));
        
        //指针后移
        current+=sizeof(int32_t);
        
        //将Message名称长度放在第二个位置
        memcpy(current, &messageNameLength, sizeof(int32_t));
        
        //指针后移
        current+=sizeof(int32_t);
        
        //将协议名称放在第三个位置上
        strcpy(current,messageName.c_str());
        
        //指针后移
        current+=messageNameLength;
        
        //将Message放在第四个位置上
        msg.SerializeToArray(current,messageSize);
        
        return (int)packetLength;
        
    }
};

#if 0
int main()
{
    
    BasePBMsgHanle msghandle;
    
    msghandle.initHandles();
    
    test t;
    
    t.set_price(100.0);
    
    t.set_userid(110);
    
    t.set_time(123);
    
    person person;
    
    person.set_age(18);
    
    person.set_userid(200508);
    
    person.set_name("irons");
    
    char tmp[10*1024];
    
    BasePBMsgBuilder::sendMessageToBuffer(t, tmp, sizeof(tmp));
    
    msghandle.handle(tmp);
    
    BasePBMsgBuilder::sendMessageToBuffer(person, tmp, sizeof(tmp));
    
    msghandle.handle(tmp);
    
    cin.get();
    
    return 0;
}

#endif

    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    

